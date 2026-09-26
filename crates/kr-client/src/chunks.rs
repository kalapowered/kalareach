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
use kr_protocol::authority::FreshnessRequirement;
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

use crate::error::{ClientError, Result};
use crate::shown::Shown;

/// Where a transfer's chunks travel.
#[derive(Clone, Debug)]
pub struct ChunkRoute {
    form: Form,
}

/// The ways a route reaches a host.
#[derive(Clone, Debug)]
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
#[derive(Debug)]
pub struct ChunkLane {
    transfer_id: TransferId,
    carrier: Carrier,
}

/// What a lane's frames travel over.
#[derive(Debug)]
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
        carrier.refresh()?;
        let entry = Method::UploadChunk.entry();
        if entry.freshness == FreshnessRequirement::ActionWindow
            && carrier.window.valid_for_ms.get() == 0
        {
            return Err(ClientError::NoActionWindow);
        }
        let request_id = carrier.next_request_id();
        let mutation = MutationRequest {
            request_id,
            method: Method::UploadChunk.into(),
            method_version: entry.version,
            action_id: ActionId::new(kr_transport::random::fresh_uuid_v4()?),
            grant_id: Nullable::null(),
            target: target.clone(),
            expected: ParamsValue::empty(),
            action_window_id: carrier.window.action_window_id.clone(),
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
        carrier.refresh()?;
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

/// A connection to an environment's attachment-chunk endpoint.
#[derive(Debug)]
struct LocalCarrier {
    reader: FrameReader,
    writer: FrameWriter,
    /// The window the host last issued on this connection.
    window: ActionWindow,
    next_request: u64,
    /// Set once the connection has failed. Nothing is sent on it again: a frame read or written in
    /// part leaves nothing a later call could trust.
    ended: bool,
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
        Ok(Self {
            reader,
            writer,
            window: acknowledgement.action_window,
            next_request: 0,
            ended: false,
        })
    }

    fn next_request_id(&mut self) -> RequestId {
        self.next_request = self.next_request.saturating_add(1);
        RequestId::new(self.next_request)
    }

    /// Applies whatever the host has already sent on this connection, without waiting for more.
    ///
    /// The host renews the window on its own schedule, at half its validity, and says so on this
    /// connection whether or not a call is in flight. A lane that sat idle past its window's
    /// validity has the renewal waiting unread, so it is read here, before the next call is built,
    /// rather than after that call has gone out under a window that expired while the lane waited.
    /// The reader keeps a frame it has only partly read, so stopping at the first frame that is not
    /// complete loses nothing.
    fn refresh(&mut self) -> Result<()> {
        use futures_util::FutureExt as _;

        if self.ended {
            return Err(ClientError::ConnectionEnded);
        }
        while let Some(read) = self.reader.read_message::<ControlFrame>().now_or_never() {
            let frame = match read {
                Ok(frame) => frame,
                Err(error) => return Err(self.failed(error)),
            };
            match frame {
                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                    self.window = window;
                }
                ControlFrame::Event(ControlEvent::Keepalive)
                | ControlFrame::Notification(_)
                | ControlFrame::Receipt(_) => {}
                // Nothing is outstanding, so an answer here answers nothing this lane asked.
                _ => {
                    self.ended = true;
                    return Err(refusal(
                        ErrorCode::InvalidArgument,
                        "the host sent a frame an attachment-chunk lane does not carry",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sends one frame and reads until its answer arrives, adopting a renewed window on the way.
    async fn exchange(
        &mut self,
        frame: &ControlFrame,
        request_id: RequestId,
    ) -> Result<ParamsValue> {
        if self.ended {
            return Err(ClientError::ConnectionEnded);
        }
        if let Err(error) = self.writer.write_message(frame).await {
            // A frame that could not be encoded never reached the socket, so the connection is
            // still whole; anything else may have left part of a frame on it.
            if matches!(error, kr_ipc::IpcError::Frame(_)) {
                return Err(ClientError::Ipc(error));
            }
            return Err(self.failed(error));
        }
        loop {
            let frame = match self.reader.read_message::<ControlFrame>().await {
                Ok(frame) => frame,
                Err(error) => return Err(self.failed(error)),
            };
            match frame {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(ClientError::from(error)),
                    };
                }
                // A long run of chunks outlives the window it started under, and the host renews
                // on this connection without being asked.
                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                    self.window = window;
                }
                ControlFrame::Event(ControlEvent::Keepalive) | ControlFrame::Notification(_) => {}
                // An answer that is a receipt rather than a result settles the call without the
                // result a chunk needs.
                ControlFrame::Receipt(receipt) if receipt.request_id == request_id => {
                    return Err(refusal(
                        ErrorCode::OutcomeUnknown,
                        "the host settled the call with a receipt and no result",
                    ));
                }
                ControlFrame::Receipt(_) => {}
                _ => {
                    self.ended = true;
                    return Err(refusal(
                        ErrorCode::InvalidArgument,
                        "the host sent a frame an attachment-chunk lane does not carry",
                    ));
                }
            }
        }
    }

    /// Ends this connection after a failure and says what the failure means to the caller.
    ///
    /// A socket that closed or failed is a lost connection, which a caller recovers from by asking
    /// the host what arrived. A frame the host sent that could not be read is not: the connection
    /// still ends, and the failure is reported as it is.
    fn failed(&mut self, error: kr_ipc::IpcError) -> ClientError {
        self.ended = true;
        failure_of(error)
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
