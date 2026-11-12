//! The attachment-chunk lane: where one transfer's chunks travel.
//!
//! A 1 MiB chunk does not fit a control frame. Section 23 gives chunks a stream kind of their own,
//! with its own bound of 1 MiB of chunk data plus at most 4 KiB of metadata and framing, and says
//! that the larger bound cannot be selected on a control stream. So a transfer's chunks never
//! travel on a session's control connection. [`ChunkRoute`] says where they do travel, and
//! [`ChunkLane`] is one transfer's lane there.
//!
//! On this machine the environment's controller listens on a second endpoint,
//! [`EnvironmentPaths::attachment_chunk_endpoint`], and frames that connection at the attachment
//! bound. A lane connects to it, says hello as any local client does, and keeps that connection's
//! own action window, which the host renews on it without being asked. Everything else about the
//! connection is the control endpoint's: the peer-credential authentication, the admission and the
//! answers.
//!
//! A paired host takes a transfer's chunks on a data stream of the control connection's own, of
//! kind `attachment_chunks`, which is a bulk stream beside the control stream. [`ChunkRoute::network`]
//! first asks the host whether it takes that stream, and says so by name when it does not, before
//! anything is reserved or opened. A lane there is one stream, with the same turn-taking: a frame,
//! then its answer on the same stream. The stream runs under the connection's registration, grant
//! and windows, so a chunk carries the window the control connection's reader last received, and
//! its request identifier comes from the same counter as the session's.
//!
//! A network lane opens its stream for a call once it has the window that call carries. A wait for
//! a window can last as long as a window's validity, which is longer than the host lets a stream
//! stand idle, so a lane that has to wait gives up the stream it holds before it waits, and opens
//! another for the call: while it waits it holds no stream, and none of the connection's bulk
//! slots.
//!
//! The client owns the bound on every wait for a paired host in a lane: the open of the stream
//! (thirty seconds), which waits for the host's credit and writes the header, and a chunk's write
//! with the wait for its answer (two minutes together). A host that gives no credit, or holds a
//! chunk and never answers, ends the lane, whose stream is reset and dropped at once; the driver
//! reads what the host holds and goes on.
//!
//! What travels is the control union. A chunk is an ordinary `upload.chunk` mutation, with its own
//! action identifier, window and requested lifetime, and a read of one is an ordinary
//! `download.chunk` request, so both go through the host's admission like every other call. A lane
//! is bound to one transfer and refuses to carry another's chunk, which is the rule a network
//! stream's header states for the stream.
//!
//! A lane verifies chunks, not files. A downloaded chunk is handed back only when it is exactly
//! the chunk `download.begin` described; the total size, the whole-file digest, the temporary file
//! and the choice to overwrite belong to whoever publishes the download.

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, EnvironmentId, RequestId, TransferId};
use kr_protocol::local::{LocalClientKind, LocalHello, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, CanonicalSet, Digest256, DurationMs, Nullable};
use kr_protocol::transfer::{
    ChunkDescriptor, DownloadChunkParams, DownloadChunkResult, TransferStreamsParams,
    TransferStreamsResult, UploadChunkParams, UploadChunkResult,
};
use kr_transport::TransportError;
use kr_transport::deadlines::{DeadlineKind, Deadlines, TimerDeadlines};
use kr_transport::streams::DataStream;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::error::{ClientError, Result};
use crate::session::{Issued, LaneSupport, Session};
use crate::shown::Shown;
use crate::transport::{ControlTransport, StreamOpener};

/// Where a transfer's chunks travel.
#[derive(Clone)]
pub struct ChunkRoute {
    form: Form,
}

/// The ways a route reaches a host.
#[derive(Clone)]
enum Form {
    /// The attachment-chunk endpoint of an environment on this machine.
    Local {
        endpoint: Endpoint,
        environment_id: EnvironmentId,
        build_id: BuildId,
    },
    /// Data streams of a paired host's connection.
    Network(Arc<Network>),
}

/// What the lanes of a network route share.
#[derive(Clone)]
struct Network {
    transport: Arc<dyn ControlTransport>,
    opener: Arc<dyn StreamOpener>,
    windows: Arc<WindowSource>,
    requests: Arc<AtomicU64>,
    environment_id: EnvironmentId,
    bounds: Arc<dyn Deadlines>,
    /// Seams this crate's own tests act through.
    #[cfg(feature = "testing")]
    seam: Seam,
}

/// What a network route's tests can do to its lanes.
#[cfg(feature = "testing")]
#[derive(Clone, Default)]
struct Seam {
    /// Ends the first lane's stream with a reset once it has carried this many chunks.
    reset_first_lane_after: Option<u64>,
    /// Set once a lane has taken the reset above.
    reset_taken: Arc<std::sync::atomic::AtomicBool>,
}

/// The refusal a host of an earlier build, and one that takes no attachment stream, are both told.
const NO_ATTACHMENT_STREAM: &str =
    "this host does not accept an attachment stream from a device; update it";

impl ChunkRoute {
    /// The attachment-chunk endpoint of an environment on this machine.
    ///
    /// `build_id` is what the lane declares in its hello, which is the build the client's control
    /// connection declares.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Ipc`] when the endpoint's address does not fit the platform's socket
    /// address.
    pub fn local(environment: &EnvironmentPaths, build_id: BuildId) -> Result<Self> {
        Ok(Self {
            form: Form::Local {
                endpoint: environment.attachment_chunk_endpoint()?,
                environment_id: environment.environment_id(),
                build_id,
            },
        })
    }

    /// The data streams of the paired host `session` is connected to.
    ///
    /// Nothing is reserved or opened before the host has said it takes the stream: a session whose
    /// transport has no data streams is refused before anything is asked, and then one read
    /// (`transfer.streams`) asks the host which streams it takes from a device. The read is not
    /// signalled, so a host of an earlier build that refuses it does not start the review of a
    /// connection that holds the right it reads under. `environment_id` is the environment the
    /// session's host belongs to, which every stream's header names.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` for a session whose transport has no data streams, such as one on
    /// this machine, whose chunks go on [`ChunkRoute::local`]; `UNSUPPORTED_CAPABILITY`, whose words
    /// tell the person to update the host, when the host of an earlier build refuses the read as
    /// one it does not list or answers that it does not take `attachment_chunks`; and any other
    /// refusal or failure of the read as it is.
    pub async fn network(session: &Session, environment_id: EnvironmentId) -> Result<Self> {
        let LaneSupport {
            windows,
            requests,
            transport,
        } = session.lane_support();
        let Some(opener) = transport.stream_opener() else {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "this connection has no data streams; its chunks go on the local route",
            ));
        };
        match session
            .read_unsignalled::<_, TransferStreamsResult>(
                Method::TransferStreams,
                &TransferStreamsParams {},
            )
            .await
        {
            Ok(taken)
                if taken
                    .accepted_streams
                    .contains(&StreamKind::AttachmentChunks) => {}
            Ok(_) => {
                return Err(refusal(
                    ErrorCode::UnsupportedCapability,
                    NO_ATTACHMENT_STREAM,
                ));
            }
            // The refusal of a method the host does not list, which is how a host of an earlier
            // build answers. Only that one is the host's age: another refusal says its own reason.
            Err(ClientError::Host(refused))
                if refused.code == ErrorCode::PermissionDenied
                    && refused.message == kr_transport::actor::METHOD_NOT_AVAILABLE =>
            {
                return Err(refusal(
                    ErrorCode::UnsupportedCapability,
                    NO_ATTACHMENT_STREAM,
                ));
            }
            Err(error) => return Err(error),
        }
        Ok(Self {
            form: Form::Network(Arc::new(Network {
                transport,
                opener,
                windows: Arc::new(WindowSource::new(windows)),
                requests,
                environment_id,
                bounds: Arc::new(lane_bounds()),
                #[cfg(feature = "testing")]
                seam: Seam::default(),
            })),
        })
    }

    /// Opens a lane for one transfer.
    ///
    /// # Errors
    ///
    /// On a local route, returns [`ClientError::Ipc`] when nothing answers at the endpoint or the
    /// host refuses the caller, the host's refusal of the hello, and a refusal when the host that
    /// answered belongs to another environment or shares no protocol major with this client.
    ///
    /// A network route opens nothing here: the lane opens its stream for its first call, which is
    /// where the failures of the open are returned ([`ChunkLane::send_chunk`]).
    pub async fn open(&self, transfer_id: TransferId) -> Result<ChunkLane> {
        match &self.form {
            Form::Local {
                endpoint,
                environment_id,
                build_id,
            } => Ok(ChunkLane {
                transfer_id,
                carrier: Carrier::Local(
                    LocalCarrier::connect(endpoint, *environment_id, build_id.clone()).await?,
                ),
            }),
            Form::Network(network) => {
                let header = StreamHeader {
                    kind: StreamKind::AttachmentChunks,
                    connection_id: network.transport.connection_id(),
                    stream_id: Nullable::null(),
                    resource: StreamResource {
                        environment_id: network.environment_id,
                        session_id: Nullable::null(),
                        attachment_id: Nullable::null(),
                        transfer_id: Nullable::some(transfer_id),
                    },
                };
                Ok(ChunkLane {
                    transfer_id,
                    carrier: Carrier::Network(Box::new(NetworkCarrier::new(network, header))),
                })
            }
        }
    }

    /// Replaces the bounds a network route's lanes wait under, for this crate's own tests, which
    /// fire them by what the lane is waiting for and never wait for a time.
    ///
    /// # Panics
    ///
    /// Panics when the route is not a network route.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn bounded_by(mut self, bounds: Arc<dyn Deadlines>) -> Self {
        let Form::Network(network) = &mut self.form else {
            panic!("only a network route has bounds");
        };
        Arc::make_mut(network).bounds = bounds;
        self
    }

    /// Makes the first lane this network route opens end its stream with a reset once it has
    /// carried `chunks` chunks, as a client does that abandons a stream, for this crate's own
    /// tests.
    ///
    /// # Panics
    ///
    /// Panics when the route is not a network route.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn resetting_first_lane_after(mut self, chunks: u64) -> Self {
        let Form::Network(network) = &mut self.form else {
            panic!("only a network route has streams to reset");
        };
        Arc::make_mut(network).seam.reset_first_lane_after = Some(chunks);
        self
    }
}

/// Runs `wait` until it ends or until a deadline of `kind` from `bounds` has passed, in which case
/// the wait is dropped and the failure names the deadline.
async fn bounded<T>(
    bounds: &dyn Deadlines,
    kind: DeadlineKind,
    wait: impl Future<Output = Result<T>>,
) -> Result<T> {
    let passed = bounds.start(kind);
    tokio::pin!(wait);
    tokio::select! {
        biased;
        outcome = &mut wait => outcome,
        () = passed => Err(ClientError::Transport(TransportError::Deadline(kind))),
    }
}

/// One transfer's lane.
///
/// Calls on it are answered in turn: a chunk is sent and its answer read before the next one goes.
/// Once its connection has failed, every later call fails with [`ClientError::ConnectionEnded`]
/// without sending anything, and the caller opens another lane.
pub struct ChunkLane {
    transfer_id: TransferId,
    carrier: Carrier,
}

crate::debug_fields!(ChunkLane { transfer_id });

/// What a lane's frames travel over.
enum Carrier {
    Local(LocalCarrier),
    Network(Box<NetworkCarrier>),
}

impl Carrier {
    /// Says whether this lane can still carry a call, before one is built.
    fn usable(&mut self) -> Result<()> {
        match self {
            Self::Local(carrier) => carrier.usable(),
            Self::Network(carrier) => carrier.usable(),
        }
    }

    /// The window a call carries.
    async fn window(&mut self) -> Result<ActionWindow> {
        match self {
            Self::Local(carrier) => carrier.window().await,
            Self::Network(carrier) => carrier.window().await,
        }
    }

    fn next_request_id(&mut self) -> RequestId {
        match self {
            Self::Local(carrier) => carrier.next_request_id(),
            Self::Network(carrier) => carrier.next_request_id(),
        }
    }

    /// Sends one frame and returns the result its answer carries.
    async fn exchange(
        &mut self,
        frame: &ControlFrame,
        request_id: RequestId,
    ) -> Result<ParamsValue> {
        match self {
            Self::Local(carrier) => carrier.exchange(frame, request_id).await,
            Self::Network(carrier) => carrier.exchange(frame, request_id).await,
        }
    }
}

impl ChunkLane {
    /// The transfer this lane carries.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Takes this lane's reading of time out of the runtime's hands and puts it `by` after the
    /// moment the lane was opened, for this crate's own tests: it stands there until this is
    /// called again, and a window the lane holds falls due, or runs out, by that reading, without
    /// the test waiting for it. On a local lane the windows it receives from then on are stamped
    /// with it; a network lane takes its windows from the session, which stamps them with the
    /// runtime's clock.
    #[cfg(feature = "testing")]
    pub fn hold_clock_at(&self, by: Duration) {
        let clock = match &self.carrier {
            Carrier::Local(carrier) => &carrier.clock,
            Carrier::Network(carrier) => &carrier.clock,
        };
        let by_ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        clock.ahead_ms.store(by_ms, Ordering::Release);
        clock.held.store(true, Ordering::Release);
    }

    /// Sends one chunk of an upload and returns what the host accepted.
    ///
    /// The chunk is an `upload.chunk` mutation of its own: a fresh action identifier, the lane's
    /// current window, and the target and requested lifetime the caller gives, which are the ones
    /// the upload's other calls use.
    ///
    /// # Errors
    ///
    /// Returns a refusal, before anything is sent, for a chunk of another transfer;
    /// [`ClientError::NoActionWindow`] when the host has issued none, or the window the lane holds
    /// was turned down or ran out before another came; [`ClientError::ConnectionEnded`] when the
    /// connection failed, whether or not the host received the chunk; the host's own refusal under
    /// its code; and a refusal when the answer names another transfer or chunk.
    ///
    /// On a paired host's connection, a transport that records why this device ended the connection
    /// (a sign-out) has that reason returned as [`ClientError::Host`] in place of whatever the lane
    /// saw first: the wait for a window, the open and the exchange all end through it.
    ///
    /// A call of a lane on a paired host's connection that has no stream (the first call, and a call
    /// that followed a wait for a window) also opens the lane's stream, once it has its window, and
    /// returns what the open fails with: a transport failure (`ControlLost` when the connection's
    /// streams were revoked, a deadline of the header kind when the host gave no credit for the
    /// stream or did not take its header within thirty seconds, a stream failure when the host reset
    /// it), and the bulk-limit refusal when the connection already holds as many transfer streams
    /// as it allows. The lane has ended then, as it has when any call fails on the connection.
    pub async fn send_chunk(
        &mut self,
        target: &ActionTarget,
        params: &UploadChunkParams,
        requested_ttl: DurationMs,
    ) -> Result<UploadChunkResult> {
        if params.transfer_id != self.transfer_id {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "this lane carries another transfer's chunks",
            ));
        }
        let carrier = &mut self.carrier;
        carrier.usable()?;
        let entry = Method::UploadChunk.entry();
        let window = carrier.window().await?;
        let request_id = carrier.next_request_id();
        let mutation = MutationRequest {
            request_id,
            method: Method::UploadChunk.into(),
            method_version: entry.version,
            action_id: ActionId::new(kr_transport::random::fresh_uuid_v4()?),
            grant_id: Nullable::null(),
            target: target.clone(),
            expected: ParamsValue::empty(),
            action_window_id: window.action_window_id,
            requested_ttl_ms: requested_ttl,
            params: ParamsValue::from_typed(params)?,
        };
        let answer = carrier
            .exchange(&ControlFrame::Mutation(Box::new(mutation)), request_id)
            .await?;
        let accepted: UploadChunkResult = answer.to_typed()?;
        if accepted.transfer_id != self.transfer_id || accepted.index != params.chunk.index {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "the host acknowledged a chunk this lane did not send",
            ));
        }
        Ok(accepted)
    }

    /// Reads one chunk of a download, and returns its bytes once they are the chunk `expected`
    /// describes.
    ///
    /// `expected` is one of the descriptors `download.begin` listed. The answer has to carry this
    /// lane's transfer and exactly that descriptor, and its bytes have to have that length and that
    /// SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ConnectionEnded`] when the connection failed, the host's own refusal
    /// under its code, and `ATTACHMENT_INTEGRITY` when the answer is not the chunk described. On a
    /// paired host's connection a call that has no stream opens the lane's stream, and returns the
    /// failures of the open that [`ChunkLane::send_chunk`] names, and the reason this device ended
    /// the connection, as [`ClientError::Host`], when the transport recorded one.
    pub async fn read_chunk(&mut self, expected: &ChunkDescriptor) -> Result<Bytes> {
        let carrier = &mut self.carrier;
        carrier.usable()?;
        let request_id = carrier.next_request_id();
        let request = Request {
            request_id,
            method: Method::DownloadChunk.into(),
            method_version: Method::DownloadChunk.entry().version,
            params: ParamsValue::from_typed(&DownloadChunkParams {
                transfer_id: self.transfer_id,
                index: expected.index,
            })?,
        };
        let answer = carrier
            .exchange(&ControlFrame::Request(request), request_id)
            .await?;
        let chunk: DownloadChunkResult = answer.to_typed()?;
        if chunk.transfer_id != self.transfer_id {
            return Err(refusal(
                ErrorCode::AttachmentIntegrity,
                "the host answered with another transfer's chunk",
            ));
        }
        if chunk.chunk != *expected {
            return Err(refusal(
                ErrorCode::AttachmentIntegrity,
                "the host's chunk is not the one the download described",
            ));
        }
        if chunk.bytes.len() as u64 != expected.byte_len.get()
            || Digest256::from_bytes(kr_cbor::sha256(chunk.bytes.as_slice())) != expected.digest
        {
            return Err(refusal(
                ErrorCode::AttachmentIntegrity,
                "the chunk's bytes do not match its length and digest",
            ));
        }
        Ok(chunk.bytes)
    }
}

/// How many answers the reader holds for a lane before it decides the host is answering calls the
/// lane never made.
///
/// Calls on a lane go one at a time, so one answer is waiting at most, and another for each call a
/// caller abandoned before its answer came.
const ANSWER_DEPTH: usize = 8;

/// Where a lane reads time from: the runtime's clock. A test of this crate's can take one lane's
/// reading out of the runtime's hands (`ChunkLane::hold_clock_at`): from then on it stands where
/// the test puts it, so that a window falls due, or runs out, by the lane's own reading when the
/// test says and not when the machine gets there. Every other lane reads the runtime's clock.
#[derive(Clone)]
struct LaneClock {
    #[cfg(feature = "testing")]
    opened: tokio::time::Instant,
    #[cfg(feature = "testing")]
    held: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "testing")]
    ahead_ms: Arc<AtomicU64>,
}

impl LaneClock {
    /// The reading of a lane opened at `opened`, the moment its first window is stamped with too.
    #[cfg_attr(
        not(feature = "testing"),
        expect(
            clippy::missing_const_for_fn,
            reason = "the shipped form holds nothing of `opened`"
        )
    )]
    fn new(opened: tokio::time::Instant) -> Self {
        #[cfg(not(feature = "testing"))]
        let _ = opened;
        Self {
            #[cfg(feature = "testing")]
            opened,
            #[cfg(feature = "testing")]
            held: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "testing")]
            ahead_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(feature = "testing")]
    fn now(&self) -> tokio::time::Instant {
        if self.held.load(Ordering::Acquire) {
            self.opened + Duration::from_millis(self.ahead_ms.load(Ordering::Acquire))
        } else {
            tokio::time::Instant::now()
        }
    }

    #[cfg(not(feature = "testing"))]
    #[expect(
        clippy::unused_self,
        reason = "it is the shipped form of a method that reads this lane's own reading"
    )]
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    /// The moment on the runtime's timer at which the window that runs out at `expiry`, by this
    /// lane's reading, has run out. That is `expiry` itself, an absolute moment of the runtime's
    /// clock, except where a test holds the lane's reading: then it is the time that reading says
    /// is left, from now.
    #[cfg(feature = "testing")]
    fn timer_deadline(&self, expiry: tokio::time::Instant) -> tokio::time::Instant {
        if self.held.load(Ordering::Acquire) {
            tokio::time::Instant::now() + expiry.saturating_duration_since(self.now())
        } else {
            expiry
        }
    }

    #[cfg(not(feature = "testing"))]
    #[expect(
        clippy::unused_self,
        reason = "it is the shipped form of a method that reads this lane's own reading"
    )]
    const fn timer_deadline(&self, expiry: tokio::time::Instant) -> tokio::time::Instant {
        expiry
    }
}

/// A window the host issued on a lane's connection, stamped with the lane's reading of time.
fn issued_at(window: ActionWindow, clock: &LaneClock) -> Issued {
    Issued {
        window,
        received_at: clock.now(),
    }
}

/// A connection to an environment's attachment-chunk endpoint.
///
/// One task reads the connection for as long as the lane lives, as a session's reader reads its
/// control connection: it applies each window the host renews as the renewal arrives, and hands
/// every answer to the call waiting for it, after checking the answer is to a call this lane made.
///
/// Which window a call carries is decided by time rather than by how far the reader has got. The
/// host issues a window for a stated validity and renews it when half of that has passed, so a
/// call carries the newest window while the lane received it less than half its validity ago; an
/// older one is due for renewal, and the call waits for the reader to deliver the renewal, until
/// the window it holds would have expired by this lane's clock. A lane whose window runs out
/// unrenewed has lost its connection. This keeps a lane from spending a call on a window it can
/// see is due. It cannot see the host's clock: a pause between the host issuing a window and this
/// lane reading it, or a suspension this lane's clock does not count, can leave the host holding a
/// window expired that the lane took for young. The host refuses a chunk under it, and the upload's
/// driver sends that chunk once more on a new lane ([`crate::uploads::send`]).
struct LocalCarrier {
    writer: FrameWriter,
    /// The newest window the reader has delivered. Its sender is the reader's, so it also says
    /// when the reader has stopped.
    window: watch::Receiver<Issued>,
    /// The answers the reader hands over, and the failure that stopped it.
    answers: mpsc::Receiver<Result<ControlFrame>>,
    /// The newest request identifier this lane has issued, which the reader checks every answer
    /// against.
    issued: Arc<AtomicU64>,
    reader: tokio::task::JoinHandle<()>,
    /// Where this lane reads time from, which the reader reads too.
    clock: LaneClock,
    /// Set once the connection has failed. Nothing is sent on it again: a frame read or written in
    /// part leaves nothing a later call could trust.
    ended: bool,
}

impl Drop for LocalCarrier {
    fn drop(&mut self) {
        // The reader holds the read half, and the connection closes once both halves have gone.
        self.reader.abort();
    }
}

impl LocalCarrier {
    async fn connect(
        endpoint: &Endpoint,
        environment_id: EnvironmentId,
        build_id: BuildId,
    ) -> Result<Self> {
        let connection = Connection::connect(endpoint).await?;
        // The frame bound is the whole difference between this connection and a control one.
        let (mut reader, mut writer) = split(connection, StreamKind::AttachmentChunks);
        // A connection lost during the hello is lost like one lost later, so the caller recovers
        // from both the same way.
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id,
                client: LocalClientKind::Cli,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .map_err(failure_of)?;
        let acknowledgement = match reader
            .read_message::<ControlFrame>()
            .await
            .map_err(failure_of)?
        {
            ControlFrame::HelloAck(acknowledgement) => *acknowledgement,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Error(error),
                ..
            }) => return Err(ClientError::from(error)),
            _ => {
                return Err(refusal(
                    ErrorCode::InvalidArgument,
                    "the host did not acknowledge the attachment-chunk hello",
                ));
            }
        };
        if acknowledgement.selected_version.major != PROTOCOL_VERSION.major {
            return Err(refusal(
                ErrorCode::UnsupportedSchema,
                "the host shares no protocol major with this client",
            ));
        }
        // An address is only a hint about who answers. A controller of another environment, or a
        // process that is not a controller, is not where this environment's chunks go.
        if acknowledgement.environment_id != environment_id
            || acknowledgement.role != LocalRole::Controller
        {
            return Err(refusal(
                ErrorCode::PermissionDenied,
                "the attachment-chunk endpoint was answered by something other than this \
                 environment's controller",
            ));
        }
        // One reading for both: the lane's clock stands at it when a test holds the clock, and the
        // first window was received at it.
        let opened = tokio::time::Instant::now();
        let clock = LaneClock::new(opened);
        let (renewals, window) = watch::channel(Issued {
            window: acknowledgement.action_window,
            received_at: opened,
        });
        let (answering, answers) = mpsc::channel(ANSWER_DEPTH);
        let issued = Arc::new(AtomicU64::new(0));
        Ok(Self {
            writer,
            window,
            answers,
            reader: tokio::spawn(read_lane(
                reader,
                renewals,
                answering,
                Arc::clone(&issued),
                clock.clone(),
            )),
            issued,
            clock,
            ended: false,
        })
    }

    /// Says whether this lane can still carry a call, before one is built.
    ///
    /// The reader stops when the connection ends or the host sends what this lane cannot take, and
    /// a call built after that would go out on a connection nobody reads.
    fn usable(&mut self) -> Result<()> {
        if self.ended || self.reader.is_finished() {
            return Err(self.stopped());
        }
        Ok(())
    }

    /// Ends this lane and says why: what the reader said as it stopped, if it said anything.
    fn stopped(&mut self) -> ClientError {
        self.ended = true;
        loop {
            match self.answers.try_recv() {
                Ok(Err(error)) => return error,
                // An answer to a call its caller abandoned.
                Ok(Ok(_)) => {}
                Err(_) => return ClientError::ConnectionEnded,
            }
        }
    }

    /// The window a call carries: the newest, once this lane received it less than half its
    /// validity ago.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoActionWindow`] when the host issued a window that admits nothing,
    /// the reader's failure when it stopped while this waited, and
    /// [`ClientError::ConnectionEnded`] when the window this lane holds would have expired before
    /// a renewal came.
    async fn window(&mut self) -> Result<ActionWindow> {
        match newest_window(&mut self.window, &self.clock, None).await {
            Ok(window) => Ok(window),
            Err(Unavailable::Nothing) => Err(ClientError::NoActionWindow),
            Err(Unavailable::SourceEnded) => Err(self.stopped()),
            Err(Unavailable::RanOut) => {
                self.ended = true;
                Err(ClientError::ConnectionEnded)
            }
        }
    }

    fn next_request_id(&mut self) -> RequestId {
        // Recorded before the request can leave, so the reader never takes the answer to it for
        // one to a call this lane did not make.
        RequestId::new(self.issued.fetch_add(1, Ordering::AcqRel).saturating_add(1))
    }

    /// Sends one frame and waits for the reader to hand over its answer.
    async fn exchange(
        &mut self,
        frame: &ControlFrame,
        request_id: RequestId,
    ) -> Result<ParamsValue> {
        if self.ended {
            return Err(ClientError::ConnectionEnded);
        }
        // The write is abandoned if the reader stops while it waits: a host that stopped reading
        // and said something this lane cannot take would otherwise hold the write for ever.
        let mut reading = self.window.clone();
        let written = {
            let write = self.writer.write_message(frame);
            tokio::pin!(write);
            loop {
                tokio::select! {
                    written = &mut write => break Some(written),
                    changed = reading.changed() => {
                        if changed.is_err() {
                            break None;
                        }
                    }
                }
            }
        };
        match written {
            Some(Ok(())) => {}
            // A frame that could not be encoded never reached the socket, so the connection is
            // still whole; anything else may have left part of a frame on it.
            Some(Err(error)) if matches!(error, kr_ipc::IpcError::Frame(_)) => {
                return Err(ClientError::Ipc(error));
            }
            Some(Err(error)) => {
                self.ended = true;
                return Err(failure_of(error));
            }
            None => return Err(self.stopped()),
        }
        loop {
            let answer = match self.answers.recv().await {
                Some(Ok(answer)) => answer,
                Some(Err(error)) => {
                    self.ended = true;
                    return Err(error);
                }
                None => {
                    self.ended = true;
                    return Err(ClientError::ConnectionEnded);
                }
            };
            match answer {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(ClientError::from(error)),
                    };
                }
                // An answer that is a receipt rather than a result settles the call without the
                // result a chunk needs.
                ControlFrame::Receipt(receipt) if receipt.request_id == request_id => {
                    return Err(refusal(
                        ErrorCode::OutcomeUnknown,
                        "the host settled the call with a receipt and no result",
                    ));
                }
                // The answer to an earlier call, which its caller abandoned before it came. The
                // reader has already refused any answer to a call this lane never made.
                _ => {}
            }
        }
    }
}

/// Why a lane has no window to carry.
enum Unavailable {
    /// The host issued a window that admits nothing.
    Nothing,
    /// The reader that delivers the windows has stopped.
    SourceEnded,
    /// The window the lane holds would have expired before a replacement came.
    RanOut,
}

/// What the lane holds, judged at this moment.
enum Held {
    /// The newest window, received less than half its validity ago and not turned down.
    Carry(ActionWindow),
    /// The host issued a window that admits nothing.
    Nothing,
    /// The renewal is due or the window was turned down: the call waits for the next one, until the
    /// window it holds would have expired.
    Renewal { expiry: tokio::time::Instant },
}

/// Judges the window the lane holds, without waiting.
fn held_window(
    issued: &mut watch::Receiver<Issued>,
    clock: &LaneClock,
    source: Option<&WindowSource>,
) -> Held {
    let held = issued.borrow_and_update().clone();
    if held.window.valid_for_ms.get() == 0 {
        return Held::Nothing;
    }
    // A paired host's window is held to the protocol's longest, so that a host that states a
    // longer one cannot keep a lane waiting on a refused window past that.
    let validity = if source.is_some() {
        held.validity().min(Duration::from_millis(
            kr_protocol::limits::MAX_ACTION_WINDOW.get(),
        ))
    } else {
        held.validity()
    };
    let turned_down =
        source.is_some_and(|source| source.turned_down(&held.window.action_window_id));
    if !turned_down && clock.now().saturating_duration_since(held.received_at) < validity / 2 {
        return Held::Carry(held.window);
    }
    Held::Renewal {
        expiry: held.received_at + validity,
    }
}

/// The window a call carries: the newest the host issued, once the lane has received it less than
/// half its validity ago.
///
/// The host issues a window for a stated validity and renews it when half of that has passed, so an
/// older one is due for renewal, and the call waits for the renewal until the window it holds would
/// have expired by the lane's clock. A window the host turned down is waited out in the same way
/// whatever its age: only one it issued since can be carried.
async fn newest_window(
    issued: &mut watch::Receiver<Issued>,
    clock: &LaneClock,
    source: Option<&WindowSource>,
) -> std::result::Result<ActionWindow, Unavailable> {
    loop {
        let expiry = match held_window(issued, clock, source) {
            Held::Carry(window) => return Ok(window),
            Held::Nothing => return Err(Unavailable::Nothing),
            // The reader delivers the next window as soon as it arrives.
            Held::Renewal { expiry } => expiry,
        };
        match tokio::time::timeout_at(clock.timer_deadline(expiry), issued.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(Unavailable::SourceEnded),
            Err(_) => return Err(Unavailable::RanOut),
        }
    }
}

/// Where the lanes of one network route take their windows from: the windows the control
/// connection's reader delivers, and the newest window the host turned down.
///
/// The marker is here and not in a lane because the driver drops a lane that failed before it sends
/// the chunk again. A lane opened after would find the same window still the newest, send it
/// once more and be refused again, so the replacement reads the route's marker and waits for a
/// window with another identifier.
struct WindowSource {
    issued: watch::Receiver<Issued>,
    turned_down: std::sync::Mutex<Option<ActionWindowId>>,
    /// Runs inside [`WindowSource::turn_down`], between its check and its update.
    #[cfg(test)]
    between_check_and_update: Option<Box<dyn Fn() + Send + Sync>>,
    /// Runs inside [`WindowSource::turn_down`], once it holds the marker's lock and before its check.
    #[cfg(test)]
    after_lock: Option<Box<dyn Fn() + Send + Sync>>,
}

impl WindowSource {
    const fn new(issued: watch::Receiver<Issued>) -> Self {
        Self {
            issued,
            turned_down: std::sync::Mutex::new(None),
            #[cfg(test)]
            between_check_and_update: None,
            #[cfg(test)]
            after_lock: None,
        }
    }

    fn turned_down(&self, window: &ActionWindowId) -> bool {
        self.turned_down
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            == Some(window)
    }

    /// Records that the host refused `window`, when it is the newest the host issued. Lanes of one
    /// route answer in any order, and a window that is no longer the newest is never carried
    /// again, so the late refusal of an older one must not replace the refusal of the current one.
    ///
    /// The check and the update are one step under the marker's lock. With the lock taken only for
    /// the update, a refusal of an older window could pass its check, wait while the newer window
    /// is issued and refused by another lane, and then replace that refusal: a lane opened after
    /// would carry the refused newer window again.
    fn turn_down(&self, window: &ActionWindowId) {
        let mut marker = self
            .turned_down
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        if let Some(hook) = &self.after_lock {
            hook();
        }
        if self.issued.borrow().window.action_window_id != *window {
            return;
        }
        #[cfg(test)]
        if let Some(hook) = &self.between_check_and_update {
            hook();
        }
        *marker = Some(window.clone());
    }
}

/// How long the open of a stream may take: the wait for the host's stream credit, which the host
/// grants once it has decided to take the device's streams (its own lookup is bounded at ten
/// seconds), and the write of the header.
const OPEN_BOUND: Duration = Duration::from_secs(30);

/// How long a chunk may take, counted from the start of its write to the end of its answer. The
/// write ends when the connection has taken the frame into its buffer, which a chunk of about a
/// mebibyte fits, so the frame travels while the lane waits for the answer: this bound covers the
/// link and the host's turn together, and a link slower than about nine kibibytes a second cannot
/// carry a chunk in it.
const CHUNK_BOUND: Duration = Duration::from_secs(120);

/// The bounds a network lane waits under: the stream's header phase is the open, and the wait for
/// the next frame, begun with the write of the chunk, is the chunk's.
fn lane_bounds() -> TimerDeadlines {
    TimerDeadlines {
        header: OPEN_BOUND,
        idle: CHUNK_BOUND,
        ..TimerDeadlines::default()
    }
}

/// A data stream of a paired host's connection, as one transfer's lane.
///
/// One stream carries the transfer's chunks in turn: a frame, then its answer on the same stream.
/// The window a chunk carries is the control connection's newest, taken as a local lane takes its
/// own, and its request identifier comes from the session's counter. The stream is opened for a
/// call after the lane has the window that call carries. A wait for a window can outlast what the
/// host lets an open stream stand idle, and a stream held through it would be reset when the chunk
/// went on it, so a lane that has carried a chunk and has to wait for its next window finishes its
/// stream first; the lane is between calls then, and the host reads a clean end.
///
/// Every wait on the host is under a bound of the lane's own: the open and the write of the header,
/// and a chunk's write with the wait for its answer. A bound that passes ends the lane, which
/// resets and drops its stream at once, so the host stops waiting for a frame and the bulk slot is
/// free for the next whether or not the caller still holds the lane.
struct NetworkCarrier {
    stream: LaneStream,
    opener: Arc<dyn StreamOpener>,
    issued: watch::Receiver<Issued>,
    source: Arc<WindowSource>,
    clock: LaneClock,
    requests: Arc<AtomicU64>,
    transport: Arc<dyn ControlTransport>,
    bounds: Arc<dyn Deadlines>,
    /// Set from before a call is written until its answer has been read whole, and once the lane
    /// has failed. A frame abandoned part way, or a call dropped before its answer came, leaves
    /// nothing a later call could trust.
    ended: bool,
    #[cfg(feature = "testing")]
    reset_after: Option<u64>,
    #[cfg(feature = "testing")]
    carried: u64,
}

/// Where a network lane's stream stands.
enum LaneStream {
    /// Not opened, because the lane has not carried a call yet or gave its stream up before a wait
    /// for a window: the header the next open writes.
    Unopened(StreamHeader),
    Open(DataStream),
    /// Reset and dropped when the lane ended.
    Ended,
}

impl Drop for NetworkCarrier {
    fn drop(&mut self) {
        // A call dropped before its answer was read whole leaves a stream the host may be part way
        // through reading, which is reset so that it stops. One dropped between calls is finished
        // and the host reads a clean end.
        if self.ended
            && let LaneStream::Open(stream) = &self.stream
        {
            stream.handle().revoke();
        }
    }
}

impl NetworkCarrier {
    fn new(network: &Network, header: StreamHeader) -> Self {
        #[cfg(feature = "testing")]
        let reset_after = network.seam.reset_first_lane_after.filter(|_| {
            !network
                .seam
                .reset_taken
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        });
        Self {
            stream: LaneStream::Unopened(header),
            opener: Arc::clone(&network.opener),
            issued: network.windows.issued.clone(),
            source: Arc::clone(&network.windows),
            clock: LaneClock::new(tokio::time::Instant::now()),
            requests: Arc::clone(&network.requests),
            transport: Arc::clone(&network.transport),
            bounds: Arc::clone(&network.bounds),
            ended: false,
            #[cfg(feature = "testing")]
            reset_after,
            #[cfg(feature = "testing")]
            carried: 0,
        }
    }

    /// Says whether this lane can still carry a call, before one is built.
    ///
    /// The transport is asked each time: the sign-in the connection was opened under can end after
    /// the lane opened, and the next chunk then stops with the reason the transport recorded.
    fn usable(&mut self) -> Result<()> {
        // The transport is asked first, by `end`: a sign-out that ended the connection also revoked
        // its streams, and the reason it recorded is what the caller is told.
        if self.transport.ended_by_this_device().is_some()
            || self.ended
            || match &self.stream {
                LaneStream::Unopened(_) => false,
                LaneStream::Open(stream) => stream.is_revoked(),
                LaneStream::Ended => true,
            }
        {
            return Err(self.end(ClientError::ConnectionEnded));
        }
        Ok(())
    }

    /// Ends this lane: nothing more goes on it, and its stream is reset and dropped, so that the
    /// host stops waiting for a frame and the stream's bulk slot is free.
    ///
    /// When the transport records why this device ended the connection, that reason is what the
    /// caller is told, whatever the lane saw first: a sign-out revokes the streams, and a lane
    /// waiting on one sees the revocation and not the sign-out.
    fn end(&mut self, error: ClientError) -> ClientError {
        self.ended = true;
        if let LaneStream::Open(stream) = std::mem::replace(&mut self.stream, LaneStream::Ended) {
            stream.reset();
        }
        self.transport
            .ended_by_this_device()
            .map_or(error, ClientError::Host)
    }

    /// The window a call carries.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoActionWindow`] when the host issued a window that admits nothing,
    /// or the one this lane holds would have expired, or was turned down, before another came (the
    /// lane has ended then), [`ClientError::ConnectionEnded`] when the session's reader stopped
    /// while this waited, and [`ClientError::Host`] with the reason this device ended the
    /// connection when the transport recorded one.
    async fn window(&mut self) -> Result<ActionWindow> {
        if matches!(self.stream, LaneStream::Ended) {
            return Err(ClientError::ConnectionEnded);
        }
        match held_window(&mut self.issued, &self.clock, Some(&self.source)) {
            Held::Carry(window) => return Ok(window),
            Held::Nothing => return Err(ClientError::NoActionWindow),
            Held::Renewal { .. } => {}
        }
        // The call has to wait for a window. A lane that has carried a chunk holds a stream, and the
        // host resets one that stands idle for far less than a renewal can take. The lane is between
        // calls, so the stream gives way before the wait and finishes cleanly, and the call opens
        // another once it has its window. A lane that waits holds no stream.
        if let LaneStream::Open(stream) = &self.stream {
            self.stream = LaneStream::Unopened(stream.header().clone());
        }
        // The wait for a renewal ends with the connection: the session keeps its windows after its
        // reader stops, so what says the connection is gone is the revocation of the connection's
        // streams, which a lane that holds no stream sees through the opener.
        let waited = tokio::select! {
            window = newest_window(&mut self.issued, &self.clock, Some(&self.source)) => Some(window),
            () = self.opener.revoked() => None,
        };
        match waited {
            Some(Ok(window)) => Ok(window),
            Some(Err(Unavailable::Nothing)) => Err(ClientError::NoActionWindow),
            Some(Err(Unavailable::RanOut)) => Err(self.end(ClientError::NoActionWindow)),
            Some(Err(Unavailable::SourceEnded)) | None => {
                Err(self.end(ClientError::ConnectionEnded))
            }
        }
    }

    fn next_request_id(&self) -> RequestId {
        RequestId::new(self.requests.fetch_add(1, Ordering::AcqRel))
    }

    /// Opens the lane's stream when the lane has none yet. The open waits for the host's credit
    /// while it holds one of the connection's four bulk slots, and the header is written to a host
    /// that has to take it: both under the one bound, and a bound that passes gives the slot back.
    async fn open_stream(&mut self) -> Result<()> {
        if let LaneStream::Unopened(header) = &self.stream {
            let opened = bounded(
                self.bounds.as_ref(),
                DeadlineKind::Header,
                self.opener.open(header.clone()),
            )
            .await?;
            self.stream = LaneStream::Open(opened);
        }
        Ok(())
    }

    /// Opens the stream the first call needs, writes one frame, reads the one answer that comes
    /// back on the same stream, and checks it answers this call.
    async fn exchange(
        &mut self,
        frame: &ControlFrame,
        request_id: RequestId,
    ) -> Result<ParamsValue> {
        if self.ended {
            return Err(self.end(ClientError::ConnectionEnded));
        }
        self.ended = true;
        if let Err(error) = self.open_stream().await {
            return Err(self.end(error));
        }
        let LaneStream::Open(stream) = &mut self.stream else {
            return Err(self.end(ClientError::ConnectionEnded));
        };
        let bounds = Arc::clone(&self.bounds);
        // The write and the wait for the answer are one bound: the write ends when the connection
        // has buffered the frame, and the frame goes to the host while the answer is awaited.
        let answer = match bounded(bounds.as_ref(), DeadlineKind::Idle, async {
            stream
                .write_message(frame)
                .await
                .map_err(ClientError::from)?;
            stream
                .read_message::<ControlFrame>()
                .await
                .map_err(ClientError::from)
        })
        .await
        {
            Ok(Some(answer)) => answer,
            Ok(None) => return Err(self.end(ClientError::ConnectionEnded)),
            Err(error) => return Err(self.end(error)),
        };
        match answer {
            ControlFrame::Response(response) if response.request_id == request_id => {
                self.ended = false;
                #[cfg(feature = "testing")]
                self.carried_one();
                match response.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(error) => {
                        // A refusal as not permitted is how a host refuses a window that has
                        // expired. This window is not carried again, by this lane or the lane
                        // that replaces it.
                        if error.code == ErrorCode::PermissionDenied
                            && let ControlFrame::Mutation(mutation) = frame
                        {
                            self.source.turn_down(&mutation.action_window_id);
                        }
                        Err(ClientError::from(error))
                    }
                }
            }
            // An answer that is a receipt rather than a result settles the call without the
            // result a chunk needs.
            ControlFrame::Receipt(receipt) if receipt.request_id == request_id => {
                self.ended = false;
                Err(refusal(
                    ErrorCode::OutcomeUnknown,
                    "the host settled the call with a receipt and no result",
                ))
            }
            // The stream carries one call at a time, so an answer to another is the host's mistake.
            _ => Err(self.end(refusal(
                ErrorCode::InvalidArgument,
                "the host answered a call this lane did not make",
            ))),
        }
    }

    /// Counts an answered chunk, and ends the stream with a reset once the count a test asked for
    /// has been carried.
    #[cfg(feature = "testing")]
    fn carried_one(&mut self) {
        self.carried += 1;
        if self.reset_after == Some(self.carried)
            && let LaneStream::Open(stream) = &self.stream
        {
            stream.handle().revoke();
        }
    }
}

/// Reads a lane's connection until it ends: each renewed window goes to the lane at once, and
/// each answer to a call the lane made goes to the call waiting for it.
async fn read_lane(
    mut reader: FrameReader,
    renewals: watch::Sender<Issued>,
    answering: mpsc::Sender<Result<ControlFrame>>,
    issued: Arc<AtomicU64>,
    clock: LaneClock,
) {
    loop {
        let frame = match reader.read_message::<ControlFrame>().await {
            Ok(frame) => frame,
            Err(error) => {
                let _ = answering.try_send(Err(failure_of(error)));
                return;
            }
        };
        let answered = match &frame {
            ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                renewals.send_replace(issued_at(window.clone(), &clock));
                continue;
            }
            ControlFrame::Event(ControlEvent::Keepalive) | ControlFrame::Notification(_) => {
                continue;
            }
            ControlFrame::Response(response) => response.request_id,
            ControlFrame::Receipt(receipt) => receipt.request_id,
            _ => {
                let _ = answering.try_send(Err(refusal(
                    ErrorCode::InvalidArgument,
                    "the host sent a frame an attachment-chunk lane does not carry",
                )));
                return;
            }
        };
        // An answer to a request this lane has not issued answers nothing it asked, whatever the
        // host meant by it. A lane waits for one answer at a time, so a host that fills the queue
        // with answers nobody is waiting for is not answering this lane either.
        if answered.get() > issued.load(Ordering::Acquire) {
            let _ = answering.try_send(Err(refusal(
                ErrorCode::InvalidArgument,
                "the host answered a call this lane did not make",
            )));
            return;
        }
        if answering.try_send(Ok(frame)).is_err() {
            return;
        }
    }
}

/// What a failed read or write on a lane's socket means to the caller.
fn failure_of(error: kr_ipc::IpcError) -> ClientError {
    match error {
        kr_ipc::IpcError::Socket { .. }
        | kr_ipc::IpcError::PeerClosed
        | kr_ipc::IpcError::TruncatedFrame { .. } => ClientError::ConnectionEnded,
        other => ClientError::Ipc(other),
    }
}

fn refusal(code: ErrorCode, message: &'static str) -> ClientError {
    ClientError::refusal(code, Shown::said(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader of a lane stops at a frame the lane cannot carry, and a lane whose reader has
    /// stopped is not usable: a call built after that would go out on a connection nobody reads.
    ///
    /// The host acknowledges the hello and then sends a second acknowledgement, which a lane does
    /// not carry. The test waits for the reader's own task to end, so `usable()`, the first step
    /// of a call, is asked after the reader has stopped and before the lane has failed. Unix
    /// only: the suites that drive a lane from a scripted host are not run on Windows.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_lane_whose_reader_has_stopped_is_not_usable() {
        use kr_protocol::identity::{BootIdentity, BootIdentitySource};
        use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
        use kr_protocol::local::{LocalHelloAck, LocalPeer};
        use kr_protocol::scalars::{TimestampMs, U64, Uuid};

        let host = kr_ipc::testing::TempHost::create();
        let environment_id = host.environment_id();
        let endpoint = host
            .environment()
            .attachment_chunk_endpoint()
            .expect("an address");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let acknowledgement = ControlFrame::HelloAck(Box::new(LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Controller,
            connection_id: ConnectionId::new(Uuid::from_bytes([42; 16])),
            environment_id,
            boot_identity: BootIdentity {
                source: BootIdentitySource::BootTime,
                value: Bytes::new(vec![1, 2, 3, 4]),
            },
            peer: LocalPeer {
                uid: U64::new(0),
                gid: U64::new(0),
                pid: Nullable::null(),
            },
            action_window: ActionWindow {
                action_window_id: ActionWindowId::new("window-1").expect("a window identifier"),
                connection_id: ConnectionId::new(Uuid::from_bytes([42; 16])),
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(0),
                valid_for_ms: DurationMs::new(60_000),
            },
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            build: None,
        }));
        let serving = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) = split(connection, StreamKind::AttachmentChunks);
            let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
                return;
            };
            writer
                .write_message(&acknowledgement)
                .await
                .expect("the acknowledgement");
            writer
                .write_message(&acknowledgement)
                .await
                .expect("the frame a lane does not carry");
            // Held open: the lane's side decides how it ends.
            let _ = reader.read_message::<ControlFrame>().await;
        });
        let build = BuildId::new("kr-test/0").expect("a build");
        let mut carrier = LocalCarrier::connect(&endpoint, environment_id, build)
            .await
            .expect("a lane");

        tokio::time::timeout(Duration::from_secs(120), &mut carrier.reader)
            .await
            .expect("the reader stops: a wait that never ends fails the test, and measures nothing")
            .expect("the reader's task");
        let refused = carrier
            .usable()
            .expect_err("a lane whose reader has stopped");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument, "{refused}");
        assert!(
            matches!(carrier.usable(), Err(ClientError::ConnectionEnded)),
            "and it stays unusable"
        );
        serving.abort();
    }

    /// A window as the lane's reader delivers it.
    fn issued_as(name: &str) -> Issued {
        Issued {
            window: ActionWindow {
                action_window_id: ActionWindowId::new(name).expect("a window"),
                connection_id: kr_protocol::ids::ConnectionId::new(
                    kr_protocol::scalars::Uuid::from_bytes([1; 16]),
                ),
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                valid_for_ms: DurationMs::new(60_000),
            },
            received_at: tokio::time::Instant::now(),
        }
    }

    /// Two lanes of one route answer in any order: the refusal of an older window, arriving after
    /// the refusal of the current one, leaves the current one refused.
    #[test]
    fn a_late_refusal_of_an_older_window_leaves_the_current_one_refused() {
        let (_issued, held) = watch::channel(issued_as("current"));
        let source = WindowSource::new(held);
        let current = ActionWindowId::new("current").expect("a window");
        let older = ActionWindowId::new("older").expect("a window");
        source.turn_down(&current);
        source.turn_down(&older);
        assert!(source.turned_down(&current), "the current refusal is kept");
        assert!(
            !source.turned_down(&older),
            "an older window is never carried"
        );
    }

    /// Two lanes of one route, in the order that loses a refusal when the check and the update are
    /// two steps. The lane that carried the then-newest window is refused, passes its check and is
    /// parked there; the host issues the next window and another lane has that one refused; the
    /// parked lane then goes on. The newer refusal has to stand: a lane opened after carries the
    /// window the host turned down last, and the host refuses it again.
    ///
    /// The step that makes the order impossible is the one lock: while the older refusal is parked,
    /// the marker's lock is held, which the case asks from its own thread, so the result does not
    /// depend on when the other threads are scheduled.
    #[test]
    fn a_refusal_cannot_replace_a_newer_one_between_its_check_and_its_update() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;

        let (issued, held) = watch::channel(issued_as("older"));
        let (parked, is_parked) = mpsc::channel::<()>();
        let (release, released) = mpsc::channel::<()>();
        let released = std::sync::Mutex::new(released);
        let first = AtomicBool::new(true);
        let mut source = WindowSource::new(held);
        source.between_check_and_update = Some(Box::new(move || {
            if first.swap(false, Ordering::AcqRel) {
                parked.send(()).expect("the case waits for the park");
                let _ = released.lock().expect("the release").recv();
            }
        }));
        let source = Arc::new(source);
        let older = ActionWindowId::new("older").expect("a window");
        let newer = ActionWindowId::new("newer").expect("a window");

        let older_lane = {
            let source = Arc::clone(&source);
            std::thread::spawn(move || source.turn_down(&older))
        };
        is_parked
            .recv()
            .expect("the older refusal is parked between its check and its update");
        assert!(
            matches!(
                source.turned_down.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ),
            "the older refusal holds the marker's lock between its check and its update"
        );
        issued.send_replace(issued_as("newer"));
        let newer_lane = {
            let source = Arc::clone(&source);
            let newer = newer.clone();
            std::thread::spawn(move || source.turn_down(&newer))
        };
        release.send(()).expect("the parked refusal goes on");
        older_lane.join().expect("the older refusal ends");
        newer_lane.join().expect("the newer refusal ends");
        assert!(
            source.turned_down(&newer),
            "the older refusal did not replace the newer one"
        );
    }

    /// The check is made with the lock held and after it was taken, not before: a refusal whose
    /// window stops being the newest while it takes the lock is dropped, whatever the order in which
    /// the lanes ran. The hook issues the next window at the one point where a check made earlier
    /// would already have passed, which is as the lock is taken.
    #[test]
    fn a_refusal_is_checked_against_the_newest_window_once_it_holds_the_lock() {
        let (issued, held) = watch::channel(issued_as("older"));
        let mut source = WindowSource::new(held);
        source.after_lock = Some(Box::new(move || {
            issued.send_replace(issued_as("newer"));
        }));
        let older = ActionWindowId::new("older").expect("a window");
        source.turn_down(&older);
        assert!(
            !source.turned_down(&older),
            "a window that stopped being the newest while the refusal took the lock is not kept"
        );
    }

    #[test]
    fn a_full_chunk_fits_the_lane_and_not_a_control_connection() {
        let chunk = kr_protocol::limits::UPLOAD_CHUNK_LEN;
        let mutation = MutationRequest {
            request_id: RequestId::new(1),
            method: Method::UploadChunk.into(),
            method_version: Method::UploadChunk.entry().version,
            action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(EnvironmentId::new(
                kr_protocol::scalars::Uuid::from_bytes([2; 16]),
            )),
            expected: ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                .expect("a window identifier"),
            requested_ttl_ms: DurationMs::new(60_000),
            params: ParamsValue::from_typed(&UploadChunkParams {
                transfer_id: TransferId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16])),
                chunk: ChunkDescriptor {
                    index: kr_protocol::scalars::U64::new(0),
                    byte_len: kr_protocol::scalars::U64::new(chunk as u64),
                    digest: Digest256::from_bytes([4; 32]),
                },
                bytes: Bytes::new(vec![5; chunk]),
            })
            .expect("chunk parameters"),
        };
        let frame = ControlFrame::Mutation(Box::new(mutation));
        assert!(
            kr_protocol::frame::FrameCodec::new(StreamKind::Control)
                .encode_message(&frame)
                .is_err(),
            "a full chunk does not fit a control frame"
        );
        kr_protocol::frame::FrameCodec::new(StreamKind::AttachmentChunks)
            .encode_message(&frame)
            .expect("a full chunk fits the attachment bound");
    }

    #[test]
    fn a_lost_socket_is_a_lost_connection_and_a_bad_frame_is_not() {
        for error in [
            kr_ipc::IpcError::PeerClosed,
            kr_ipc::IpcError::TruncatedFrame {
                received: 1,
                expected: 4,
            },
            kr_ipc::IpcError::socket(
                "read",
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            ),
        ] {
            assert!(matches!(failure_of(error), ClientError::ConnectionEnded));
        }
        assert!(matches!(
            failure_of(kr_ipc::IpcError::UnexpectedMessage(
                "a frame this lane does not read"
            )),
            ClientError::Ipc(_)
        ));
    }
}
