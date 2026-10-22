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
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, StreamKind};
use kr_protocol::hello::{ProtocolVersion, ReceiveLimits};
use kr_protocol::ids::{ActionId, BuildId, RequestId};
use kr_protocol::local::{
    BridgeOrigin, LocalBuild, LocalClientKind, LocalHello, LocalHelloAck, LocalRole,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::retained::{Level, stated_protocol, worker_protocols_for};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::wire::WireMessage;
use kr_protocol::worker::{
    ControllerGenerationToken, GenerationAccepted, WorkerDescriptor, WorkerVerifyProof,
};

use crate::endpoint::Connection;
use crate::error::{IpcError, Result};
use crate::framed::{FrameReader, FrameWriter, split};
use crate::paths::Endpoint;
use crate::verify::{check_proof, fresh_challenge};

/// How a client reads and writes its frames.
///
/// A client is under this release's own level ([`ThisLevel`]), as every client of the host is but
/// one kind; or it is a control daemon's link to a worker ([`Bound`]), and speaks the level that
/// worker stated, through the retained codec of that level. The two differ in their types, and not
/// in a value tried at run time, so that a link to a worker has no way to the raw halves of its
/// stream: a frame written to a worker is written through its level or not at all.
pub trait Codec: Copy + std::fmt::Debug + Send + Sync + 'static {
    /// The level frames are read and written under.
    fn level(self) -> Level;
}

/// This release's own level.
#[derive(Clone, Copy, Debug)]
pub struct ThisLevel;

impl Codec for ThisLevel {
    fn level(self) -> Level {
        Level::this()
    }
}

/// The level of the worker a control daemon's link speaks to.
#[derive(Clone, Copy, Debug)]
pub struct Bound(Level);

impl Codec for Bound {
    fn level(self) -> Level {
        self.0
    }
}

/// What a hello offers, and which answers it admits.
///
/// A client admits an answer of the major it states itself. A control daemon's link to a worker, and
/// the update's look at a worker, also admit the major of a retained level, from a worker, which
/// answers its own; and the update's look at the daemon of the release it makes current also admits
/// the majors that release's manifest lists, from a control daemon. Nothing else is admitted, so a
/// client that does not name them keeps the one major it has always had.
#[derive(Clone, Debug)]
struct Offer {
    /// The versions offered: the client's own first.
    versions: Vec<ProtocolVersion>,
    /// Whether an answer from a worker of another offered major is admitted.
    from_workers: bool,
    /// The majors, besides the client's own, that an answer from a control daemon may state.
    from_daemons: Vec<u16>,
}

impl Offer {
    /// A client that offers `own` alone and admits its major alone.
    fn own(own: ProtocolVersion) -> Self {
        Self {
            versions: vec![own],
            from_workers: false,
            from_daemons: Vec::new(),
        }
    }

    /// A client that reaches a worker: it offers `own` and the protocol of each level it retains,
    /// and admits the major of any of them from a worker.
    fn to_workers(own: ProtocolVersion) -> Self {
        Self {
            versions: worker_protocols_for(own),
            from_workers: true,
            from_daemons: Vec::new(),
        }
    }

    /// A client that looks at the control daemon of a release which lists `majors`: it offers `own`
    /// and the first version of each of those majors, and admits a control daemon's answer of one
    /// of them.
    fn to_daemons(own: ProtocolVersion, majors: &[u16]) -> Self {
        let mut versions = vec![own];
        for major in majors {
            let version = ProtocolVersion::new(*major, 0);
            if *major != own.major && !versions.contains(&version) {
                versions.push(version);
            }
        }
        Self {
            versions,
            from_workers: false,
            from_daemons: majors.to_vec(),
        }
    }

    /// The version the client states as its own.
    fn own_version(&self) -> ProtocolVersion {
        self.versions[0]
    }

    /// Whether an answer that selects `selected`, from a process in `role`, is admitted.
    fn admits(&self, selected: ProtocolVersion, role: LocalRole) -> bool {
        selected.major == self.own_version().major
            || (self.from_workers
                && role == LocalRole::Worker
                && self.versions.iter().any(|v| v.major == selected.major))
            || (role == LocalRole::Controller && self.from_daemons.contains(&selected.major))
    }
}

/// A connected local client.
pub type LocalClient = Client<ThisLevel>;

/// A control daemon's link to one worker, bound to the level the worker stated.
pub type BoundLink = Client<Bound>;

/// A control daemon found by [`LocalClient::connect_listing`].
#[derive(Debug)]
pub enum Listed {
    /// The daemon states this build's major, and this is the client of it.
    Ours(Box<LocalClient>),
    /// The daemon states another major that the release it belongs to lists. There is no client:
    /// the hello's answer is all there is to read, and nothing can be sent.
    Other(Box<LocalHelloAck>),
}

impl Listed {
    /// What the daemon said in its answer to the hello.
    #[must_use]
    pub const fn acknowledgement(&self) -> &LocalHelloAck {
        match self {
            Self::Ours(client) => &client.acknowledgement,
            Self::Other(acknowledgement) => acknowledgement,
        }
    }
}

/// A worker seen by [`LocalClient::look_at_worker`]: it can be proved to be the one a session
/// names and asked what build it is, and it can be sent nothing else.
#[derive(Debug)]
pub struct WorkerLook {
    client: LocalClient,
}

impl WorkerLook {
    /// Proves the worker is the one `descriptor` names.
    ///
    /// # Errors
    ///
    /// Returns what [`Client::verify_worker`] returns.
    pub async fn verify_worker(
        &mut self,
        descriptor: &WorkerDescriptor,
    ) -> Result<WorkerVerifyProof> {
        self.client.verify_worker(descriptor).await
    }

    /// Challenges the worker for a key the caller already holds.
    ///
    /// # Errors
    ///
    /// Returns what [`Client::challenge_worker`] returns.
    pub async fn challenge_worker(
        &mut self,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        session_id: kr_protocol::ids::SessionId,
        session_epoch: kr_protocol::ids::SessionEpoch,
        endpoint: &str,
    ) -> Result<WorkerVerifyProof> {
        self.client
            .challenge_worker(worker_public_key, session_id, session_epoch, endpoint)
            .await
    }

    /// The build the worker stated in its answer to the hello, if it stated one.
    #[must_use]
    pub const fn build(&self) -> Option<&LocalBuild> {
        self.client.acknowledgement.build.as_ref()
    }
}

/// A connected local client, under a codec.
#[derive(Debug)]
pub struct Client<C: Codec> {
    codec: C,
    reader: FrameReader,
    writer: FrameWriter,
    acknowledgement: LocalHelloAck,
    generation_challenge: Option<kr_protocol::worker::GenerationChallenge>,
    next_request: u64,
    /// What the host pushed while one of this client's own calls was outstanding.
    ///
    /// A call reads frames until its answer arrives, and what it reads on the way is this
    /// connection's subscription, not an answer to anything: it is kept here, oldest first, and
    /// handed back by [`Client::take_held`] or by the next [`Client::recv`]. Both drain this before
    /// the socket, so a frame the host sent first is never delivered after one it sent afterwards.
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

    /// Connects as the helper of a process bridge, on behalf of an invoker in another environment.
    ///
    /// The hello says where the invocation originally entered, so the host at this end knows the
    /// connection arrived over a bridge and keeps the rules only it can keep. The declaration is a
    /// record and a restriction and never authority: this host authenticates the connection by the
    /// operating-system credentials of its peer, as it does for every local client.
    ///
    /// # Errors
    ///
    /// Returns what [`LocalClient::connect`] returns, and the host's refusal of an origin it does
    /// not admit.
    pub async fn connect_for_bridge(
        endpoint: &Endpoint,
        build_id: BuildId,
        origin: BridgeOrigin,
    ) -> Result<Self> {
        Self::connecting(
            endpoint,
            LocalClientKind::Cli,
            build_id,
            ReceiveLimits::default(),
            Some(origin),
            &Offer::own(stated_protocol()),
        )
        .await
    }

    /// Connects to a worker to see what it is, and stops there.
    ///
    /// A worker of a build this one retains the level of may state another public major than this
    /// build's own, and a client that offers only its own is refused by it before it can say which
    /// build it is. This offers the protocol of each level this build retains as well, so the
    /// worker answers its own, and the update can read its build and decide from it. The look has
    /// no request to make of the worker: it proves the worker and reads its build, which are frozen
    /// exchanges every level reads, and nothing else.
    ///
    /// # Errors
    ///
    /// Returns what [`LocalClient::connect`] returns.
    pub async fn look_at_worker(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
    ) -> Result<WorkerLook> {
        let client = Self::connecting(
            endpoint,
            kind,
            build_id,
            ReceiveLimits::default(),
            None,
            &Offer::to_workers(stated_protocol()),
        )
        .await?;
        Ok(WorkerLook { client })
    }

    /// Connects to the control daemon of a release that lists the public `majors`, which may state
    /// one of them and not this build's own.
    ///
    /// An update looks at the daemon of the release it makes current to see that it answers, and
    /// that release may be of another major than the updater's. The look offers those majors too
    /// and admits a control daemon's answer of one of them; a daemon that answers its own major is a
    /// client like any other, and one that answers another is only its answer to the hello, since
    /// nothing else this build says is read by a daemon of that major. With no majors this is
    /// [`LocalClient::connect`].
    ///
    /// # Errors
    ///
    /// Returns what [`LocalClient::connect`] returns.
    pub async fn connect_listing(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        majors: &[u16],
    ) -> Result<Listed> {
        if kind == LocalClientKind::Controller {
            return Err(IpcError::UnexpectedMessage(
                "a control daemon's link to a worker is made with BoundLink, which speaks the \
                 worker's level",
            ));
        }
        let stated = stated_protocol();
        let offer = Offer::to_daemons(stated, majors);
        let (reader, writer, acknowledgement) = hello(
            endpoint,
            kind,
            build_id,
            ReceiveLimits::default(),
            None,
            &offer,
        )
        .await?;
        if acknowledgement.selected_version.major != stated.major {
            return Ok(Listed::Other(Box::new(acknowledgement)));
        }
        Ok(Listed::Ours(Box::new(Self {
            codec: ThisLevel,
            reader,
            writer,
            acknowledgement,
            generation_challenge: None,
            next_request: 0,
            held: VecDeque::new(),
            held_bytes: 0,
        })))
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
        Self::connecting(
            endpoint,
            kind,
            build_id,
            max_receive,
            None,
            &Offer::own(stated_protocol()),
        )
        .await
    }

    /// Connects as a client of a build that states `own` as its protocol, whatever this build
    /// states, so that a test can talk to a daemon that states a later major as a client of that
    /// major does.
    ///
    /// # Errors
    ///
    /// Returns what [`LocalClient::connect`] returns.
    #[cfg(feature = "testing")]
    pub async fn connect_stating(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        own: ProtocolVersion,
    ) -> Result<Self> {
        Self::connecting(
            endpoint,
            kind,
            build_id,
            ReceiveLimits::default(),
            None,
            &Offer::own(own),
        )
        .await
    }

    #[cfg(not(feature = "testing"))]
    async fn connect_receiving(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        max_receive: ReceiveLimits,
    ) -> Result<Self> {
        Self::connecting(
            endpoint,
            kind,
            build_id,
            max_receive,
            None,
            &Offer::own(stated_protocol()),
        )
        .await
    }

    async fn connecting(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
        max_receive: ReceiveLimits,
        origin: Option<BridgeOrigin>,
        offer: &Offer,
    ) -> Result<Self> {
        if kind == LocalClientKind::Controller {
            return Err(IpcError::UnexpectedMessage(
                "a control daemon's link to a worker is made with BoundLink, which speaks the \
                 worker's level",
            ));
        }
        let (reader, writer, acknowledgement) =
            hello(endpoint, kind, build_id, max_receive, origin, offer).await?;
        Ok(Self {
            codec: ThisLevel,
            reader,
            writer,
            acknowledgement,
            generation_challenge: None,
            next_request: 0,
            held: VecDeque::new(),
            held_bytes: 0,
        })
    }

    /// Returns the writing half, for a caller that streams input.
    pub const fn writer(&mut self) -> &mut FrameWriter {
        &mut self.writer
    }

    /// Splits the client into its two halves.
    ///
    /// A caller that takes the halves takes the stream itself, so anything this client is still
    /// holding for it has to be collected first: drain [`Client::take_held`] until it is empty, or
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
}

/// Opens a connection and says hello, as every client does, and returns the halves of the stream
/// and the host's answer. The hello and its answer are read in this release's own shape: they are
/// what tells a control daemon the level of a worker.
async fn hello(
    endpoint: &Endpoint,
    kind: LocalClientKind,
    build_id: BuildId,
    max_receive: ReceiveLimits,
    origin: Option<BridgeOrigin>,
    offer: &Offer,
) -> Result<(FrameReader, FrameWriter, LocalHelloAck)> {
    let connection = Connection::connect(endpoint).await?;
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(LocalHello {
            offered_versions: offer.versions.clone(),
            build_id,
            client: kind,
            capabilities: CanonicalSet::new(),
            max_receive,
            origin,
        }))
        .await?;
    // The acknowledgement is read before the client exists, so there is never a moment when a
    // client holds an invented connection identity or an invented action window.
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
    if !offer.admits(acknowledgement.selected_version, acknowledgement.role) {
        return Err(IpcError::VersionMismatch {
            host: offer.own_version().to_string(),
            offered: acknowledgement.selected_version.to_string(),
        });
    }
    Ok((reader, writer, acknowledgement))
}

impl BoundLink {
    /// Connects a control daemon to a worker and binds the link to the level the worker states.
    ///
    /// The worker's answer to the hello says its level before anything else is exchanged, so a
    /// worker at a level this release does not speak at is refused here, before its challenge is
    /// read and before any generation is presented: no path that adopts a worker can take one this
    /// daemon cannot read or write the frames of. The worker offers its generation challenge as
    /// soon as a controller announces itself, so the nonce is bound to this connection from its
    /// first frame. It is held until the token is presented and used exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::UnretainedLevel`] naming what the worker stated, an error when nothing
    /// is listening or the peer is refused, and the worker's refusal of the controller connection.
    pub async fn connect(endpoint: &Endpoint, build_id: BuildId) -> Result<Self> {
        Self::connecting(endpoint, build_id, ReceiveLimits::default(), None).await
    }

    /// Connects as [`BoundLink::connect`] does and binds the link to `level`, whatever the worker
    /// states, so that a test can drive a link at a level of its own.
    ///
    /// # Errors
    ///
    /// Returns what [`BoundLink::connect`] returns, bar the refusal of the worker's level.
    #[cfg(feature = "testing")]
    pub async fn connect_at(endpoint: &Endpoint, build_id: BuildId, level: Level) -> Result<Self> {
        Self::connecting(endpoint, build_id, ReceiveLimits::default(), Some(level)).await
    }

    /// Connects and says the link can receive `max_receive`, rather than the usual limits.
    ///
    /// A worker cuts what it answers to fit what the peer said it can receive. A link a control
    /// daemon opens to carry a device's requests says what the device said it can receive, so a
    /// worker that is asked for more than the device can take refuses it there, and the daemon
    /// never relays a frame the device must discard. The daemon's own links connect with the usual
    /// limits.
    ///
    /// # Errors
    ///
    /// Returns what [`BoundLink::connect`] returns.
    pub async fn connect_receiving(
        endpoint: &Endpoint,
        build_id: BuildId,
        max_receive: ReceiveLimits,
    ) -> Result<Self> {
        Self::connecting(endpoint, build_id, max_receive, None).await
    }

    async fn connecting(
        endpoint: &Endpoint,
        build_id: BuildId,
        max_receive: ReceiveLimits,
        bound_to: Option<Level>,
    ) -> Result<Self> {
        let stated = stated_protocol();
        let (reader, writer, acknowledgement) = hello(
            endpoint,
            LocalClientKind::Controller,
            build_id,
            max_receive,
            None,
            &Offer::to_workers(stated),
        )
        .await?;
        let level = match bound_to {
            Some(level) => level,
            None => {
                let level = retained_level(acknowledgement.build.as_ref())?;
                // The two things the worker says of itself agree: the version its hello answered
                // is the one its level names, so a worker that answered a major the level does not
                // speak is not bound to it.
                let answered = acknowledgement.selected_version;
                match level.protocol() {
                    Some(named) if named.major == answered.major => {}
                    Some(named) => {
                        return Err(IpcError::OutsideLevel(format!(
                            "the worker answered protocol {answered}, and its level names {named}"
                        )));
                    }
                    None => {
                        return Err(IpcError::OutsideLevel(format!(
                            "the worker answered protocol {answered}, and its level records none"
                        )));
                    }
                }
                level
            }
        };
        let mut link = Self {
            codec: Bound(level),
            reader,
            writer,
            acknowledgement,
            generation_challenge: None,
            next_request: 0,
            held: VecDeque::new(),
            held_bytes: 0,
        };
        match link.read_frame().await? {
            ControlFrame::GenerationChallenge(challenge) => {
                link.generation_challenge = Some(challenge);
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
        Ok(link)
    }

    /// The level this link speaks.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.codec.0
    }

    /// Splits the link into its two halves, which keep the level.
    ///
    /// A caller that takes the halves takes the stream itself, so anything this link is still
    /// holding for it has to be collected first, as for [`LocalClient::into_halves`].
    #[must_use]
    pub fn into_halves(self) -> (LinkReader, LinkWriter, LocalHelloAck) {
        debug_assert!(
            self.held.is_empty(),
            "the halves are taken with {} frame(s) still held for this caller",
            self.held.len()
        );
        let level = self.codec.0;
        (
            LinkReader {
                level,
                reader: self.reader,
            },
            LinkWriter {
                level,
                writer: self.writer,
            },
            self.acknowledgement,
        )
    }
}

impl<C: Codec> Client<C> {
    /// Keeps every frame this link reads and writes from now on in `tap`, so that a test can record
    /// a real exchange.
    #[cfg(feature = "testing")]
    pub fn record_into(&mut self, tap: &crate::framed::Tap) {
        self.reader.tap_into(tap.clone());
        self.writer.tap_into(tap.clone());
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
        self.send(&ControlFrame::VerifyChallenge(challenge)).await?;
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
        self.send(&ControlFrame::VerifyChallenge(challenge)).await?;
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
        self.send(&ControlFrame::GenerationToken(Box::new(token)))
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
        let params = self.codec.level().encode_params(method, params)?;
        self.send(&ControlFrame::Request(Request {
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
        self.send(&ControlFrame::Mutation(Box::new(mutation.clone())))
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
        let params = self.codec.level().encode_params(method, params)?;
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
        self.send(&ControlFrame::Mutation(Box::new(mutation)))
            .await?;
        self.await_response(request_id).await
    }

    /// Confirms to a worker that a caller has received an action's acceptance.
    ///
    /// # Errors
    ///
    /// Returns a transport failure.
    pub async fn confirm_delivery(&mut self, action_id: ActionId) -> Result<()> {
        self.send(&ControlFrame::AcceptanceDelivered(action_id))
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
        self.acknowledged(
            &ControlFrame::AuthorityRevision(notice),
            "the worker refused the authority revision",
            |frame| match frame {
                ControlFrame::AuthorityRevisionAck(ack) => Some(ack),
                _ => None,
            },
        )
        .await
    }

    /// Tells a worker what the host's local owner may do and waits for it to acknowledge.
    ///
    /// The acknowledgement carries the sequence the worker now holds: the statement's own, or the
    /// higher one it already held.
    ///
    /// # Errors
    ///
    /// Returns the worker's refusal, or a transport failure.
    pub async fn announce_local_access(
        &mut self,
        access: kr_protocol::worker::LocalAccess,
    ) -> Result<kr_protocol::worker::LocalAccessAck> {
        self.acknowledged(
            &ControlFrame::LocalAccess(access),
            "the worker refused the statement of what the local owner may do",
            |frame| match frame {
                ControlFrame::LocalAccessAck(ack) => Some(ack),
                _ => None,
            },
        )
        .await
    }

    /// Tells a worker the environment's privacy generation and waits for its answer: the
    /// generation its session holds now, and where its own cleanup stands.
    ///
    /// # Errors
    ///
    /// Returns the worker's refusal, or a transport failure.
    pub async fn announce_privacy(
        &mut self,
        notice: kr_protocol::privacy::PrivacyGenerationNotice,
    ) -> Result<kr_protocol::privacy::PrivacyGenerationAck> {
        self.acknowledged(
            &ControlFrame::PrivacyGeneration(notice),
            "the worker refused the privacy generation",
            |frame| match frame {
                ControlFrame::PrivacyGenerationAck(ack) => Some(*ack),
                _ => None,
            },
        )
        .await
    }

    /// Writes one notice and reads until the worker acknowledges it.
    ///
    /// What arrives before the answer is this connection's subscription, not an answer to the
    /// notice: it is kept in arrival order and handed back afterwards. An error response is the
    /// worker's refusal, named by `refused`. Any other frame is the answer when `acknowledgement`
    /// takes it, and otherwise is not an answer at all.
    async fn acknowledged<T>(
        &mut self,
        notice: &ControlFrame,
        refused: &'static str,
        acknowledgement: impl FnOnce(ControlFrame) -> Option<T>,
    ) -> Result<T> {
        self.send(notice).await?;
        loop {
            match self.read_socket_frame().await? {
                ControlFrame::Notification(notification) => {
                    self.hold(ControlFrame::Notification(notification))?;
                }
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(error),
                    ..
                }) => {
                    return Err(IpcError::IdentityUnavailable {
                        what: refused,
                        detail: error.to_string(),
                    });
                }
                frame => {
                    return acknowledgement(frame).ok_or(IpcError::UnexpectedMessage(
                        "the worker answered something other than an acknowledgement",
                    ));
                }
            }
        }
    }

    /// Hands a worker one snapshot of plugin admissions, every part in order, and returns its
    /// report, every part of it, once it has applied the snapshot.
    ///
    /// Each part sent and each part received has `per_part` to go or come, so a worker that stops
    /// part way holds this connection for no more than one part's time. A report of more parts
    /// than a report may have is refused rather than read. What this returns is the report's parts
    /// as the worker sent them; judging them is the caller's. After an error the connection's
    /// position is unknown, and a caller retires it.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::IdentityUnavailable`] when the worker refused the snapshot or a part
    /// ran out of time, [`IpcError::UnexpectedMessage`] when the worker answered something other
    /// than a report, or the report's parts do not agree with each other or are too many, and
    /// whatever writing or reading failed with.
    pub async fn exchange_admissions(
        &mut self,
        parts: Vec<kr_protocol::admission::PluginAdmissions>,
        per_part: std::time::Duration,
    ) -> Result<Vec<kr_protocol::admission::PluginAdmissionsAck>> {
        let late = || IpcError::IdentityUnavailable {
            what: "the worker did not take or answer its plugin admissions in time",
            detail: format!("each part has {} ms", per_part.as_millis()),
        };
        for part in parts {
            tokio::time::timeout(
                per_part,
                self.send(&ControlFrame::PluginAdmissions(Box::new(part))),
            )
            .await
            .map_err(|_| late())??;
        }
        let mut report: Vec<kr_protocol::admission::PluginAdmissionsAck> = Vec::new();
        // The part expected next is due by one time, whatever arrives on the subscription
        // before it; only a part of the report moves it.
        let mut due = tokio::time::Instant::now() + per_part;
        loop {
            let frame = tokio::time::timeout_at(due, self.read_socket_frame())
                .await
                .map_err(|_| late())??;
            match frame {
                ControlFrame::PluginAdmissionsAck(part) => {
                    let expected = u32::try_from(report.len() + 1).unwrap_or(u32::MAX);
                    let agrees = part.part == expected
                        && report.first().is_none_or(|first| {
                            first.parts == part.parts
                                && first.frame == part.frame
                                && first.report_seq == part.report_seq
                        });
                    if !agrees
                        || part.parts == 0
                        || part.parts > kr_protocol::limits::MAX_ADMISSION_PARTS
                    {
                        return Err(IpcError::UnexpectedMessage(
                            "the worker's report on its admissions came in parts that do not agree \
                             or are more than a report may have",
                        ));
                    }
                    let done = part.part == part.parts;
                    report.push(*part);
                    if done {
                        return Ok(report);
                    }
                    due = tokio::time::Instant::now() + per_part;
                }
                // This connection's subscription, not an answer to the snapshot. It is kept in
                // arrival order and handed back afterwards.
                ControlFrame::Notification(notification) => {
                    self.hold(ControlFrame::Notification(notification))?;
                }
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(error),
                    ..
                }) => {
                    return Err(IpcError::IdentityUnavailable {
                        what: "the worker refused the plugin admissions",
                        detail: error.to_string(),
                    });
                }
                _ => {
                    return Err(IpcError::UnexpectedMessage(
                        "the worker answered its admissions with something other than a report",
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
    /// The frame carries no history scope: this is the link a local caller's own action travels,
    /// and a worker of any build reads it. A scope goes only over a proxy link, to a worker that
    /// states it holds results to one.
    ///
    /// `lease` is the remote dispatch lease the host took for a paired device's mutation, and a
    /// local caller's action, which does not depend on the lease, passes none. A link to a worker of
    /// an earlier release refuses a frame that carries one, so the lease is passed only on a link
    /// whose worker is at this build's own level.
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
        lease: Option<kr_protocol::local::ForwardedLease>,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        self.forward_for(
            mutation,
            actor,
            grant_rights,
            accepted_deadline_boot_ms,
            lease,
            None,
        )
        .await
    }

    /// Passes a workflow's `session.close` of a session it started to the worker that owns it.
    ///
    /// The mutation carries the run it acts for, which the worker compares with the run named in
    /// the session's launch provenance. The actor is the workflow's principal, scoped to its
    /// grant; the envelope names no grant, because the daemon decided the grant before it sent
    /// this and a worker holds none.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn forward_for_workflow(
        &mut self,
        mutation: &MutationRequest,
        actor: &kr_protocol::actor::ActorEnvelope,
        workflow_run_id: kr_protocol::ids::WorkflowRunId,
        accepted_deadline_boot_ms: kr_protocol::scalars::U64,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        self.forward_for(
            mutation,
            actor,
            &kr_protocol::scalars::CanonicalSet::new(),
            accepted_deadline_boot_ms,
            None,
            Some(workflow_run_id),
        )
        .await
    }

    async fn forward_for(
        &mut self,
        mutation: &MutationRequest,
        actor: &kr_protocol::actor::ActorEnvelope,
        grant_rights: &kr_protocol::scalars::CanonicalSet<kr_protocol::rights::ActionRight>,
        accepted_deadline_boot_ms: kr_protocol::scalars::U64,
        lease: Option<kr_protocol::local::ForwardedLease>,
        workflow_run_id: Option<kr_protocol::ids::WorkflowRunId>,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        if !kr_protocol::local::may_travel_to_a_worker(grant_rights) {
            return Err(IpcError::RightNotForwarded(
                kr_protocol::rights::ActionRight::VoiceUse,
            ));
        }
        let request_id = mutation.request_id;
        self.send(&ControlFrame::Forwarded(Box::new(
            kr_protocol::local::ForwardedMutation {
                mutation: mutation.clone(),
                actor: actor.clone(),
                grant_rights: grant_rights.clone(),
                accepted_deadline_boot_ms,
                history: None,
                screen_basis: None,
                workflow_run_id,
                lease,
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
            let frame: ControlFrame = self.receive().await?;
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
                frame = self.receive() => Some(frame?),
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
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(Ok(value)),
                        // A worker's refusal of this connection itself. The answer was read to its
                        // end, but nothing more can be asked over a link that no longer speaks for
                        // the generation that holds the worker, so it is the link's failure.
                        Outcome::Error(error) if error.link_fenced => Err(IpcError::LinkFenced {
                            detail: error.message,
                        }),
                        Outcome::Error(error) => Ok(Err(error)),
                    };
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

    /// Reads a worker's answer, or the parameters of a request, as the type `T` under the level
    /// this client is under. A value that does not decode is an error, never passed on.
    ///
    /// # Errors
    ///
    /// Returns what the level's surface or this build's decoder refuses.
    pub fn decode<T: WireMessage>(&self, value: &ParamsValue) -> Result<T> {
        Ok(self.codec.level().decode_value::<T>(value)?)
    }

    /// Writes one frame, as the level this client is under reads it.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::NotInLevel`] for a frame the level cannot read, which is then not
    /// written, and a transport failure.
    pub async fn send(&mut self, frame: &ControlFrame) -> Result<()> {
        let payload = self
            .codec
            .level()
            .encode(frame, &StreamKind::Control.cbor_limits())?;
        let framed = FrameCodec::new(StreamKind::Control).encode(&payload)?;
        self.writer.write_frame(&framed).await
    }

    /// Reads one frame, as the level this client is under writes it. The reader keeps its place in
    /// a frame, so a read that is cancelled resumes.
    async fn receive(&mut self) -> Result<ControlFrame> {
        let payload = self.reader.read_payload().await?;
        Ok(self
            .codec
            .level()
            .decode(&payload, &StreamKind::Control.cbor_limits())?)
    }

    fn next_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }
}

/// The level a worker is at, from what it stated in its answer to the hello.
///
/// This release speaks to a worker at its own level and at the levels it retains
/// ([`kr_protocol::retained::levels`]); a worker at any other level, and one that states no build,
/// is one an update to this release waits for rather than meets.
///
/// # Errors
///
/// Returns [`IpcError::UnretainedLevel`] naming what the worker stated.
pub fn retained_level(stated: Option<&kr_protocol::local::LocalBuild>) -> Result<Level> {
    Level::of(stated).map_err(|unretained| IpcError::UnretainedLevel {
        worker: unretained.to_string(),
        level: kr_protocol::retained::levels()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" and "),
    })
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

/// The reading half of a control daemon's link to a worker.
#[derive(Debug)]
pub struct LinkReader {
    level: Level,
    reader: FrameReader,
}

impl LinkReader {
    /// A reading half over a stream a test holds the other end of, under `level`.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn over(level: Level, reader: FrameReader) -> Self {
        Self { level, reader }
    }

    /// Reads the next frame, as the worker's level writes it.
    ///
    /// # Errors
    ///
    /// Returns a transport failure, or a frame the level's surface does not admit.
    pub async fn read(&mut self) -> Result<ControlFrame> {
        let payload = self.reader.read_payload().await?;
        Ok(self
            .level
            .decode(&payload, &StreamKind::Control.cbor_limits())?)
    }
}

/// The writing half of a control daemon's link to a worker.
///
/// It writes a [`ControlFrame`] and nothing else, as the worker's level reads it: there is no way
/// to it for bytes.
#[derive(Debug)]
pub struct LinkWriter {
    level: Level,
    writer: FrameWriter,
}

impl LinkWriter {
    /// A writing half over a stream a test holds the other end of, under `level`.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn over(level: Level, writer: FrameWriter) -> Self {
        Self { level, writer }
    }

    /// Writes one frame, as the worker's level reads it.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::NotInLevel`] for a frame the level cannot read, which is then not
    /// written, and a transport failure.
    pub async fn write(&mut self, frame: &ControlFrame) -> Result<()> {
        let payload = self
            .level
            .encode(frame, &StreamKind::Control.cbor_limits())?;
        let framed = FrameCodec::new(StreamKind::Control).encode(&payload)?;
        self.writer.write_frame(&framed).await
    }

    /// Whether a frame stopped part way through, which leaves the stream in pieces.
    #[must_use]
    pub fn is_mid_frame(&self) -> bool {
        self.writer.is_mid_frame()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: ProtocolVersion = ProtocolVersion::new(1, 0);
    const TWO: ProtocolVersion = ProtocolVersion::new(2, 0);

    /// KR-REQ-26.07: which answers a client admits. A client states one major and admits it from
    /// anyone; the majors a reach of workers offers are admitted from a worker alone; and the majors
    /// the manifest of a release lists are admitted from a control daemon alone. Nothing else is, so
    /// a client that does not name them keeps the one major it has always had.
    #[test]
    fn a_client_admits_another_major_only_from_the_peer_it_offered_it_to() {
        let own = Offer::own(TWO);
        assert!(own.admits(TWO, LocalRole::Controller));
        assert!(own.admits(TWO, LocalRole::Worker));
        assert!(
            !own.admits(ONE, LocalRole::Worker),
            "no retained major was offered"
        );
        assert!(!own.admits(ONE, LocalRole::Controller));

        let workers = Offer {
            versions: vec![TWO, ONE],
            from_workers: true,
            from_daemons: Vec::new(),
        };
        assert!(workers.admits(TWO, LocalRole::Controller));
        assert!(workers.admits(ONE, LocalRole::Worker));
        assert!(
            !workers.admits(ONE, LocalRole::Controller),
            "a daemon never answers a retained major"
        );
        assert!(!workers.admits(ProtocolVersion::new(3, 0), LocalRole::Worker));
        assert!(!workers.admits(ONE, LocalRole::Rendezvous));

        let daemons = Offer::to_daemons(ONE, &[2]);
        assert_eq!(daemons.versions, [ONE, TWO]);
        assert!(daemons.admits(ONE, LocalRole::Controller));
        assert!(daemons.admits(TWO, LocalRole::Controller));
        assert!(
            !daemons.admits(TWO, LocalRole::Worker),
            "a worker never answers a listed major"
        );
        assert!(!daemons.admits(ProtocolVersion::new(3, 0), LocalRole::Controller));
        assert_eq!(
            Offer::to_daemons(ONE, &[1]).versions,
            [ONE],
            "a release that lists this build's major adds nothing to the offer"
        );
    }
}
