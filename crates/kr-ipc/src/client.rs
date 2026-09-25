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

use std::collections::VecDeque;

use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, StreamKind};
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, BuildId, RequestId};
use kr_protocol::local::{LocalClientKind, LocalHello, LocalHelloAck};
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
    /// What the host pushed while one of this client's own calls was outstanding.
    ///
    /// A call reads frames until its answer arrives, and what it reads on the way is this
    /// connection's subscription, not an answer to anything: it is kept here, oldest first, and
    /// handed back by [`LocalClient::take_held`] or by the next [`LocalClient::recv`]. Both drain
    /// this before the socket, so a frame the host sent first is never delivered after one it sent
    /// afterwards.
    held: VecDeque<Held>,
    /// What those frames occupy on the wire, length prefixes included.
    held_bytes: usize,
}

/// One frame this client kept, with what it is charged against the connection's bound.
#[derive(Debug)]
struct Held {
    frame: ControlFrame,
    charged: usize,
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
        Self::connect_receiving(endpoint, kind, build_id, ReceiveLimits::default()).await
    }

    /// Connects and says this client can receive `max_receive`, rather than the usual limits.
    ///
    /// A host cuts what it answers to fit what the peer said it can receive, and a peer that can
    /// receive far less than usual is how that cutting is proved. Every client this product ships
    /// connects with the usual limits; this is compiled away outside this repository's own tests.
    ///
    /// # Errors
    ///
    /// Returns what [`LocalClient::connect`] returns.
    #[cfg(feature = "testing")]
    pub async fn connect_receiving(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        max_receive: ReceiveLimits,
    ) -> Result<Self> {
        Self::connecting(endpoint, kind, build_id, max_receive).await
    }

    #[cfg(not(feature = "testing"))]
    async fn connect_receiving(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        max_receive: ReceiveLimits,
    ) -> Result<Self> {
        Self::connecting(endpoint, kind, build_id, max_receive).await
    }

    async fn connecting(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        max_receive: ReceiveLimits,
    ) -> Result<Self> {
        let connection = Connection::connect(endpoint).await?;
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id,
                client: kind,
                capabilities: CanonicalSet::new(),
                max_receive,
            }))
            .await?;
        // The acknowledgement is read before the client exists, so there is never a moment when a
        // `LocalClient` holds an invented connection identity or an invented action window.
        let acknowledgement = match reader.read_message().await? {
            ControlFrame::HelloAck(acknowledgement) => *acknowledgement,
            ControlFrame::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => {
                return Err(IpcError::IdentityUnavailable {
                    what: "the host refused the connection",
                    detail: error.to_string(),
                });
            }
            _ => {
                return Err(IpcError::UnexpectedMessage(
                    "the host did not acknowledge the hello",
                ));
            }
        };
        if acknowledgement.selected_version.major != PROTOCOL_VERSION.major {
            return Err(IpcError::VersionMismatch {
                host: PROTOCOL_VERSION.to_string(),
                offered: acknowledgement.selected_version.to_string(),
            });
        }
        let mut client = Self {
            reader,
            writer,
            acknowledgement,
            generation_challenge: None,
            next_request: 0,
            held: VecDeque::new(),
            held_bytes: 0,
        };
        if kind == LocalClientKind::Controller {
            // A worker offers its generation challenge as soon as a controller announces itself, so
            // the nonce is bound to this connection from its first frame. It is held until the
            // token is presented and used exactly once.
            match client.read_frame().await? {
                ControlFrame::GenerationChallenge(challenge) => {
                    client.generation_challenge = Some(challenge);
                }
                ControlFrame::Response(Response {
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
            .write_message(&ControlFrame::VerifyChallenge(challenge))
            .await?;
        let ControlFrame::VerifyProof(proof) = self.read_frame().await? else {
            return Err(IpcError::UnexpectedMessage(
                "the worker did not answer the challenge",
            ));
        };
        check_proof(descriptor, &challenge, &proof).map_err(IpcError::from)?;
        Ok(proof)
    }

    /// Challenges the worker behind this endpoint against a key the caller already holds.
    ///
    /// This is the recovery path: a daemon whose published descriptor is missing still knows the
    /// key its own rendezvous established and the endpoint the session was given, and the answer
    /// carries every field a descriptor needs.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker does not answer, the signature does not verify, or an
    /// identity field disagrees with what the caller knows.
    pub async fn challenge_worker(
        &mut self,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        session_id: kr_protocol::ids::SessionId,
        session_epoch: kr_protocol::ids::SessionEpoch,
        endpoint: &str,
    ) -> Result<WorkerVerifyProof> {
        let challenge = fresh_challenge().map_err(IpcError::from)?;
        self.writer
            .write_message(&ControlFrame::VerifyChallenge(challenge))
            .await?;
        let ControlFrame::VerifyProof(proof) = self.read_frame().await? else {
            return Err(IpcError::UnexpectedMessage(
                "the worker did not answer the challenge",
            ));
        };
        crate::verify::check_proof_against(
            worker_public_key,
            session_id,
            session_epoch,
            endpoint,
            &challenge,
            &proof,
        )
        .map_err(IpcError::from)?;
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
            .write_message(&ControlFrame::GenerationToken(Box::new(token)))
            .await?;
        match self.read_frame().await? {
            ControlFrame::GenerationAccepted(accepted) => Ok(accepted),
            ControlFrame::Response(Response {
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

    /// Returns the action window this connection currently holds.
    ///
    /// The host issues the first window with the acknowledgement and replaces it on its own
    /// schedule, so a caller never asks for one and never computes its expiry. Section 9 refuses a
    /// first admission through an expired or unknown window, and replacing a window changes the
    /// payload digest, so a renewal is never an automatic retry of an older request.
    #[must_use]
    pub const fn action_window(&self) -> &kr_protocol::hello::ActionWindow {
        &self.acknowledgement.action_window
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
            .write_message(&ControlFrame::Request(Request {
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
        // The window this mutation will quote is taken after everything the host has already
        // pushed has been applied.
        let mutation = self.compose(method, action_id, target, params).await?;
        self.writer
            .write_message(&ControlFrame::Mutation(Box::new(mutation.clone())))
            .await?;
        self.await_response(mutation.request_id).await
    }

    /// Builds the mutation this client would send, without sending it.
    ///
    /// A caller that has to be able to ask again about what an action did keeps this and sends it
    /// with [`Self::repeat`]; everything the host de-duplicates on is in it.
    ///
    /// # Errors
    ///
    /// Returns a transport failure, or a parameter this protocol cannot encode.
    pub async fn compose<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        target: kr_protocol::envelope::ActionTarget,
        params: &T,
    ) -> Result<MutationRequest> {
        // The window this mutation will quote is taken after everything the host has already
        // pushed has been applied.
        self.absorb_pending().await?;
        let params = ParamsValue::from_typed(params)
            .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))?;
        Ok(MutationRequest {
            request_id: self.next_id(),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id,
            grant_id: Nullable::null(),
            target,
            expected: ParamsValue::empty(),
            action_window_id: self.acknowledgement.action_window.action_window_id.clone(),
            requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
            params,
        })
    }

    /// Sends a mutation again exactly as it was first sent, and returns what the host says now.
    ///
    /// This is the recovery an action identifier exists for. A caller whose answer never arrived
    /// does not know what its action did; section 23 says the host keeps the payload digest and
    /// returns the existing receipt for an exact duplicate, and that the freshness window is part
    /// of that payload. So an exact duplicate is the *original* request, window and all - not the
    /// same identifier under this connection's own window, which is a different payload and is
    /// refused as a reused identifier. The window is not re-validated for an action the host has
    /// already admitted, which is what lets this work over a new connection.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn repeat(
        &mut self,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        self.absorb_pending().await?;
        let request_id = self.next_id();
        let mut mutation = mutation.clone();
        // The only field that is this connection's rather than the action's. A response correlates
        // a request on one connection; the durable identity is the action identifier.
        mutation.request_id = request_id;
        self.writer
            .write_message(&ControlFrame::Mutation(Box::new(mutation)))
            .await?;
        self.await_response(request_id).await
    }

    /// Confirms to a worker that a caller has received an action's acceptance.
    ///
    /// # Errors
    ///
    /// Returns a transport failure.
    pub async fn confirm_delivery(&mut self, action_id: ActionId) -> Result<()> {
        self.writer
            .write_message(&ControlFrame::AcceptanceDelivered(action_id))
            .await
    }

    /// Announces the host's current authority revision and waits for the worker to install it.
    ///
    /// The acknowledgement is what makes a revocation complete for that worker: until it arrives,
    /// or the worker is confirmed ended, the revocation is still pending there.
    ///
    /// # Errors
    ///
    /// Returns the worker's refusal, or a transport failure.
    pub async fn announce_revision(
        &mut self,
        notice: kr_protocol::worker::AuthorityRevisionNotice,
    ) -> Result<kr_protocol::worker::AuthorityRevisionAck> {
        self.writer
            .write_message(&ControlFrame::AuthorityRevision(notice))
            .await?;
        loop {
            match self.read_socket_frame().await? {
                ControlFrame::AuthorityRevisionAck(ack) => return Ok(ack),
                // This connection's subscription, not an answer to the revision. It is kept in
                // arrival order and handed back afterwards.
                ControlFrame::Notification(notification) => {
                    self.hold(ControlFrame::Notification(notification))?;
                }
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(error),
                    ..
                }) => {
                    return Err(IpcError::IdentityUnavailable {
                        what: "the worker refused the authority revision",
                        detail: error.to_string(),
                    });
                }
                _ => {
                    return Err(IpcError::UnexpectedMessage(
                        "the worker answered something other than an acknowledgement",
                    ));
                }
            }
        }
    }

    /// Passes a mutation the host admitted to the component that owns its subject.
    ///
    /// The mutation travels unchanged, because it is what the payload digest covers and what the
    /// caller will retry with. What travels beside it is the actor the host verified, the rights of
    /// the grant it was checked against, and the deadline it accepted; the deadline is on the
    /// machine's own continuous clock so both processes read the same instant.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn forward(
        &mut self,
        mutation: &MutationRequest,
        actor: &kr_protocol::actor::ActorEnvelope,
        grant_rights: &kr_protocol::scalars::CanonicalSet<kr_protocol::rights::ActionRight>,
        accepted_deadline_boot_ms: kr_protocol::scalars::U64,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        if !kr_protocol::local::may_travel_to_a_worker(grant_rights) {
            return Err(IpcError::RightNotForwarded(
                kr_protocol::rights::ActionRight::VoiceUse,
            ));
        }
        let request_id = mutation.request_id;
        self.writer
            .write_message(&ControlFrame::Forwarded(Box::new(
                kr_protocol::local::ForwardedMutation {
                    mutation: mutation.clone(),
                    actor: actor.clone(),
                    grant_rights: grant_rights.clone(),
                    accepted_deadline_boot_ms,
                },
            )))
            .await?;
        self.await_response(request_id).await
    }

    /// Reads the next frame, which may be a notification.
    ///
    /// Anything the host pushed while one of this client's own calls was outstanding comes out
    /// here first, oldest first, before another byte is read from the socket. A window the host
    /// pushed is applied rather than returned: it is the connection's own resource, not an answer
    /// to anything a caller asked for.
    ///
    /// # Errors
    ///
    /// Returns a transport failure.
    pub async fn recv(&mut self) -> Result<ControlFrame> {
        self.read_frame().await
    }

    /// Returns how many frames the host pushed while a call of this client's own was outstanding.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Takes the oldest frame the host pushed while a call of this client's own was outstanding.
    ///
    /// This is what a caller asks after a call to learn what it was told during it, without
    /// reading the socket and without waiting for anything further to arrive. [`Self::recv`]
    /// returns the same frames in the same order for a caller that is reading the stream anyway.
    pub fn take_held(&mut self) -> Option<ControlFrame> {
        let held = self.held.pop_front()?;
        self.held_bytes = self.held_bytes.saturating_sub(held.charged);
        Some(held.frame)
    }

    /// Returns the writing half, for a caller that streams input.
    pub const fn writer(&mut self) -> &mut FrameWriter {
        &mut self.writer
    }

    /// Splits the client into its two halves.
    ///
    /// A caller that takes the halves takes the stream itself, so anything this client is still
    /// holding for it has to be collected first: drain [`Self::take_held`] until it is empty, or
    /// split before the first call. Both callers in this workspace split a connection they have
    /// only just opened, where nothing has been pushed yet.
    #[must_use]
    pub fn into_halves(self) -> (FrameReader, FrameWriter, LocalHelloAck) {
        debug_assert!(
            self.held.is_empty(),
            "the halves are taken with {} frame(s) still held for this caller",
            self.held.len()
        );
        (self.reader, self.writer, self.acknowledgement)
    }

    /// Returns the next frame of this connection's stream, held or freshly read.
    ///
    /// What a call kept comes first, because it arrived first. Only when nothing is held does this
    /// reach the socket.
    async fn read_frame(&mut self) -> Result<ControlFrame> {
        if let Some(frame) = self.take_held() {
            return Ok(frame);
        }
        self.read_socket_frame().await
    }

    /// Reads one frame off the socket, applying anything that belongs to the connection rather
    /// than to a caller.
    ///
    /// The host renews this connection's action window without being asked, at half the window's
    /// validity. Absorbing that here is what lets every call site read frames without each of them
    /// having to know about a resource none of them asked for. The reader keeps its position
    /// inside a frame, so a cancelled read resumes rather than restarting, and a renewal that has
    /// already been applied is not lost by the cancellation.
    ///
    /// A caller waiting for its own answer reads through this rather than through
    /// [`Self::read_frame`], so that what it keeps on the way is appended behind whatever is
    /// already held instead of being read back out in front of it.
    async fn read_socket_frame(&mut self) -> Result<ControlFrame> {
        loop {
            let frame: ControlFrame = self.reader.read_message().await?;
            match frame {
                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                    self.acknowledgement.action_window = window;
                }
                // A keepalive carries nothing; its arrival is the whole message. Returning it
                // would make every caller that is waiting for an answer treat it as one.
                ControlFrame::Event(ControlEvent::Keepalive) => {}
                other => return Ok(other),
            }
        }
    }

    /// Keeps a frame that arrived while a call of this client's own was outstanding.
    ///
    /// Section 9 has a peer that cannot keep up told rather than waited for, so what this holds is
    /// bounded by the send queue the connection negotiated - the most the host would have queued
    /// for this peer before resynchronising it - and a client that reaches the bound is told
    /// instead of quietly losing the oldest of what it was sent.
    ///
    /// # Errors
    ///
    /// Returns a failure naming the bound when this connection is already holding it.
    fn hold(&mut self, frame: ControlFrame) -> Result<()> {
        let charged = charge(&frame);
        let ceiling = self.held_ceiling();
        let held = self.held_bytes.saturating_add(charged);
        if held > ceiling {
            return Err(IpcError::socket(
                "hold what the host pushed while this call was outstanding",
                std::io::Error::other(format!(
                    "{held} bytes over this connection's {ceiling}-byte bound"
                )),
            ));
        }
        self.held_bytes = held;
        self.held.push_back(Held { frame, charged });
        Ok(())
    }

    /// What this client may hold for its caller, in bytes.
    ///
    /// What the connection negotiated, never more than the protocol's own bound: a host that
    /// stated a smaller send queue is taken at its word, and one that states a larger figure does
    /// not thereby enlarge what a client keeps in memory.
    fn held_ceiling(&self) -> usize {
        usize::try_from(self.acknowledgement.max_receive.max_send_queue_bytes.get())
            .unwrap_or(kr_protocol::limits::MAX_SEND_QUEUE_BYTES)
            .min(kr_protocol::limits::MAX_SEND_QUEUE_BYTES)
    }

    /// Applies anything the host has already pushed, without waiting for more.
    ///
    /// A connection that has been idle for longer than a window's validity has its replacement
    /// waiting in the socket. Reading it before a mutation is built is what stops that mutation
    /// quoting a window the host has already replaced: section 9 refuses a first admission through
    /// an expired window, and replacing the window of a request that has already been submitted is
    /// not allowed either, so the only place to take the current one is before the request exists.
    async fn absorb_pending(&mut self) -> Result<()> {
        loop {
            // Biased, so the reader is polled first and the ready arm only wins when there is
            // nothing waiting. The reader keeps its position inside a frame, so losing this race
            // part way through a frame costs nothing.
            let frame: Option<ControlFrame> = tokio::select! {
                biased;
                frame = self.reader.read_message::<ControlFrame>() => Some(frame?),
                () = std::future::ready(()) => None,
            };
            match frame {
                Some(ControlFrame::Event(ControlEvent::ActionWindowRenewed(window))) => {
                    self.acknowledgement.action_window = window;
                }
                Some(ControlFrame::Event(ControlEvent::Keepalive)) => {}
                // Anything else is an answer or an event a caller wants. It has left the socket,
                // so it is kept for whoever asks next rather than lost here, and this stops at it:
                // a renewal behind it waits for the next read, which is where it was before.
                Some(other) => {
                    self.hold(other)?;
                    return Ok(());
                }
                None => return Ok(()),
            }
        }
    }

    async fn await_response(
        &mut self,
        request_id: RequestId,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        loop {
            match self.read_socket_frame().await? {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return Ok(match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    });
                }
                // A notification that arrives while a call is outstanding is not an answer to it.
                // It is this connection's subscription, so it is kept in the order it arrived and
                // handed back afterwards rather than dropped for having been badly timed.
                ControlFrame::Notification(notification) => {
                    self.hold(ControlFrame::Notification(notification))?;
                }
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

/// What a frame occupies on the wire, its four-byte length prefix included.
///
/// A count of frames is not a bound on memory: one notification can carry a whole batch of output,
/// so the bound is in the same bytes section 9 states a send queue in. A frame that cannot be
/// encoded is charged everything, which refuses it rather than admitting something unmeasured.
fn charge(frame: &ControlFrame) -> usize {
    kr_cbor::to_canonical_value(frame)
        .map(|value| kr_cbor::encoded_len(&value).saturating_add(FRAME_LENGTH_PREFIX_LEN))
        .unwrap_or(usize::MAX)
}
