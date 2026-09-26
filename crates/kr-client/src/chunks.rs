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
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, RequestId, TransferId};
use kr_protocol::local::{LocalClientKind, LocalHello, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, CanonicalSet, Digest256, DurationMs, Nullable};
use kr_protocol::transfer::{
    ChunkDescriptor, DownloadChunkParams, DownloadChunkResult, UploadChunkParams, UploadChunkResult,
};

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::error::{ClientError, Result};
use crate::shown::Shown;

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
}

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

    /// Opens a lane for one transfer.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Ipc`] when nothing answers at the endpoint or the host refuses the
    /// caller, the host's refusal of the hello, and a refusal when the host that answered belongs
    /// to another environment or shares no protocol major with this client.
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
        }
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
}

impl ChunkLane {
    /// The transfer this lane carries.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
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
    /// [`ClientError::NoActionWindow`] when the host has issued none;
    /// [`ClientError::ConnectionEnded`] when the connection failed, whether or not the host
    /// received the chunk; the host's own refusal under its code; and a refusal when the answer
    /// names another transfer or chunk.
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
        let Carrier::Local(carrier) = &mut self.carrier;
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
    /// under its code, and `ATTACHMENT_INTEGRITY` when the answer is not the chunk described.
    pub async fn read_chunk(&mut self, expected: &ChunkDescriptor) -> Result<Bytes> {
        let Carrier::Local(carrier) = &mut self.carrier;
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

/// A window the host issued on a lane's connection, and when the lane received it.
#[derive(Clone)]
struct Issued {
    window: ActionWindow,
    received_at: tokio::time::Instant,
}

impl Issued {
    fn now(window: ActionWindow) -> Self {
        Self {
            window,
            received_at: tokio::time::Instant::now(),
        }
    }

    /// How long the host said the window stands, from when it was issued.
    fn validity(&self) -> Duration {
        Duration::from_millis(self.window.valid_for_ms.get())
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
        let (renewals, window) = watch::channel(Issued::now(acknowledgement.action_window));
        let (answering, answers) = mpsc::channel(ANSWER_DEPTH);
        let issued = Arc::new(AtomicU64::new(0));
        Ok(Self {
            writer,
            window,
            answers,
            reader: tokio::spawn(read_lane(reader, renewals, answering, Arc::clone(&issued))),
            issued,
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
        loop {
            let issued = self.window.borrow_and_update().clone();
            if issued.window.valid_for_ms.get() == 0 {
                return Err(ClientError::NoActionWindow);
            }
            let validity = issued.validity();
            if issued.received_at.elapsed() < validity / 2 {
                return Ok(issued.window);
            }
            // The renewal is due. The reader delivers it as soon as it arrives.
            let expiry = issued.received_at + validity;
            match tokio::time::timeout_at(expiry, self.window.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(self.stopped()),
                Err(_) => {
                    self.ended = true;
                    return Err(ClientError::ConnectionEnded);
                }
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

/// Reads a lane's connection until it ends: each renewed window goes to the lane at once, and
/// each answer to a call the lane made goes to the call waiting for it.
async fn read_lane(
    mut reader: FrameReader,
    renewals: watch::Sender<Issued>,
    answering: mpsc::Sender<Result<ControlFrame>>,
    issued: Arc<AtomicU64>,
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
                renewals.send_replace(Issued::now(window.clone()));
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
