//! The attachment-chunk channel.
//!
//! A 1 MiB chunk does not fit a control frame. Section 23 gives it its own stream kind with its own
//! bound, 1 MiB of chunk data plus at most 4 KiB of metadata and framing, and says outright that
//! the larger bound cannot be selected on a control stream. So chunks travel on their own stream,
//! on both transports:
//!
//! * On the network transport it is a data stream whose header declares
//!   [`kr_protocol::frame::StreamKind::AttachmentChunks`] and names the transfer, validated against
//!   the established control connection.
//! * On a local endpoint there are no streams to multiplex, so the host listens on a second
//!   endpoint beside its control endpoint and frames that connection at the attachment bound. The
//!   handshake, the peer-credential authentication and the action window are the control
//!   connection's, unchanged: what differs is the frame bound, which is the whole reason the stream
//!   exists.
//!
//! What travels is the same [`kr_protocol::envelope::ControlFrame`] union both transports carry, so
//! a chunk is an ordinary mutation with an ordinary action window and an ordinary response. That is
//! what keeps `upload.chunk` inside the host's admission path instead of beside it.

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
    Response,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, BuildId, RequestId, TransferId};
use kr_protocol::local::{LocalClientKind, LocalHello, LocalHelloAck};
use kr_protocol::method::{Method, MethodName, MethodVersion};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, DownloadChunkParams, DownloadChunkResult, UploadChunkParams, UploadChunkResult,
};

use crate::error::{Result, TransferError};

/// The role suffix the attachment-chunk endpoint is named with.
///
/// The control endpoint is `c`, the rendezvous `r` and a worker `w<display>`; `t` is this one. A
/// Unix socket address is short on macOS, which is why the name is one letter.
const ROLE: &str = "t";

/// Returns the environment's attachment-chunk endpoint.
///
/// # Errors
///
/// Returns [`TransferError::Ipc`] when the address does not fit the platform's socket address.
pub fn chunk_endpoint(paths: &EnvironmentPaths) -> Result<Endpoint> {
    #[cfg(unix)]
    {
        Endpoint::from_path(paths.runtime_dir().join(format!("{ROLE}.sock")))
            .map_err(TransferError::from)
    }
    #[cfg(windows)]
    {
        Endpoint::from_name(format!(
            "kalareach-{}-{}-{ROLE}",
            kr_ipc::paths::current_uid(),
            kr_ipc::paths::short_prefix(paths.environment_id())
        ))
        .map_err(TransferError::from)
    }
}

/// A client's connection to the attachment-chunk endpoint.
///
/// It holds the action window the host issues and replaces it whenever the host renews, so a
/// caller sending a long sequence of chunks never has to think about freshness.
#[derive(Debug)]
pub struct ChunkChannel {
    reader: FrameReader,
    writer: FrameWriter,
    acknowledgement: LocalHelloAck,
    window: ActionWindow,
    next_request: u64,
}

impl ChunkChannel {
    /// Connects to an environment's attachment-chunk endpoint and negotiates the protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Ipc`] when nothing is listening or the peer is refused, and
    /// [`TransferError::InvalidArgument`] when no protocol major is shared.
    pub async fn connect(endpoint: &Endpoint, build_id: BuildId) -> Result<Self> {
        let connection = Connection::connect(endpoint).await?;
        // The frame bound is the whole difference between this connection and a control one.
        let (mut reader, mut writer) = split(connection, StreamKind::AttachmentChunks);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id,
                client: LocalClientKind::Cli,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
            }))
            .await?;
        let acknowledgement = match reader.read_message().await? {
            ControlFrame::HelloAck(acknowledgement) => *acknowledgement,
            ControlFrame::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => {
                return Err(TransferError::PermissionDenied {
                    detail: error.to_string(),
                });
            }
            _ => {
                return Err(TransferError::invalid(
                    "the host did not acknowledge the attachment-chunk hello",
                ));
            }
        };
        if acknowledgement.selected_version.major != PROTOCOL_VERSION.major {
            return Err(TransferError::invalid(format!(
                "this host speaks protocol {}, and this client offered {PROTOCOL_VERSION}",
                acknowledgement.selected_version
            )));
        }
        let window = acknowledgement.action_window.clone();
        Ok(Self {
            reader,
            writer,
            acknowledgement,
            window,
            next_request: 0,
        })
    }

    /// Returns what the host said about this connection.
    #[must_use]
    pub const fn acknowledgement(&self) -> &LocalHelloAck {
        &self.acknowledgement
    }

    /// Sends one chunk of an upload and returns what the host accepted.
    ///
    /// # Errors
    ///
    /// Returns the host's own refusal, or [`TransferError::Ipc`] when the connection fails.
    pub async fn send_chunk(
        &mut self,
        target: &ActionTarget,
        transfer_id: TransferId,
        chunk: ChunkDescriptor,
        bytes: Bytes,
    ) -> Result<UploadChunkResult> {
        let params = UploadChunkParams {
            transfer_id,
            chunk,
            bytes,
        };
        let mutation = MutationRequest {
            request_id: self.request_id(),
            method: MethodName::from(Method::UploadChunk),
            method_version: MethodVersion(Method::UploadChunk.entry().version.0),
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: target.clone(),
            expected: ParamsValue::empty(),
            action_window_id: self.window.action_window_id.clone(),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
            params: ParamsValue::from_typed(&params)
                .map_err(|error| TransferError::invalid(error.to_string()))?,
        };
        self.writer
            .write_message(&ControlFrame::Mutation(Box::new(mutation)))
            .await?;
        self.outcome().await
    }

    /// Reads one chunk of a download.
    ///
    /// # Errors
    ///
    /// Returns the host's own refusal, or [`TransferError::Ipc`] when the connection fails.
    pub async fn read_chunk(
        &mut self,
        transfer_id: TransferId,
        index: u64,
    ) -> Result<DownloadChunkResult> {
        let params = DownloadChunkParams {
            transfer_id,
            index: U64::new(index),
        };
        let request = Request {
            request_id: self.request_id(),
            method: MethodName::from(Method::DownloadChunk),
            method_version: MethodVersion(Method::DownloadChunk.entry().version.0),
            params: ParamsValue::from_typed(&params)
                .map_err(|error| TransferError::invalid(error.to_string()))?,
        };
        self.writer
            .write_message(&ControlFrame::Request(request))
            .await?;
        self.outcome().await
    }

    fn request_id(&mut self) -> RequestId {
        self.next_request = self.next_request.saturating_add(1);
        RequestId::new(self.next_request)
    }

    /// Reads until a response arrives, applying whatever the host says about the connection.
    async fn outcome<T: kr_protocol::wire::WireMessage>(&mut self) -> Result<T> {
        loop {
            match self.reader.read_message::<ControlFrame>().await? {
                ControlFrame::Response(Response { outcome, .. }) => {
                    return match outcome {
                        Outcome::Ok(value) => value
                            .to_typed()
                            .map_err(|error| TransferError::invalid(error.to_string())),
                        Outcome::Error(error) => Err(refusal(&error)),
                    };
                }
                // A renewal replaces the window this connection holds. A long chunk sequence
                // outlives its first window, and the host renews without being asked.
                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                    self.window = window;
                }
                ControlFrame::Event(ControlEvent::Keepalive) => {}
                ControlFrame::Receipt(_) | ControlFrame::Notification(_) => {}
                _ => {
                    return Err(TransferError::invalid(
                        "the host sent a frame an attachment-chunk connection does not carry",
                    ));
                }
            }
        }
    }
}

/// Reads a host refusal back into the failure it names.
///
/// The code is what the host decided; the message is what it said. Nothing is reinterpreted, so a
/// caller sees the same category the method registry gave it.
fn refusal(error: &ProtocolError) -> TransferError {
    use kr_protocol::error::ErrorCode;

    let detail = error.message.clone();
    match error.code {
        ErrorCode::AttachmentIntegrity => TransferError::Integrity { detail },
        ErrorCode::SourceChanged => TransferError::SourceChanged { detail },
        ErrorCode::QuotaExceeded => TransferError::QuotaExceeded { detail },
        ErrorCode::DraftConflict => TransferError::DraftConflict { detail },
        ErrorCode::PermissionDenied => TransferError::PermissionDenied { detail },
        ErrorCode::EnvironmentUnavailable => TransferError::WrongEnvironment {
            named: detail.clone(),
            owned: detail,
        },
        ErrorCode::StorageUnavailable => TransferError::StoreUnavailable { detail },
        _ => TransferError::InvalidArgument(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chunk_endpoint_sits_beside_the_control_endpoint() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths =
            kr_ipc::paths::HostPaths::new(root.path().join("run"), root.path().join("state"))
                .expect("absolute roots")
                .environment(kr_protocol::ids::EnvironmentId::new(
                    kr_protocol::scalars::Uuid::from_bytes([2; 16]),
                ));
        let chunks = chunk_endpoint(&paths).expect("an addressable endpoint");
        let control = paths
            .controller_endpoint()
            .expect("an addressable endpoint");
        assert_ne!(chunks, control);
        #[cfg(unix)]
        {
            assert_eq!(chunks.as_path().parent(), control.as_path().parent());
            assert!(chunks.as_text().ends_with("/t.sock"));
        }
    }

    #[test]
    fn a_chunk_stream_carries_more_than_a_control_stream() {
        assert!(
            StreamKind::AttachmentChunks.max_frame_len() > StreamKind::Control.max_frame_len(),
            "a 1 MiB chunk plus its metadata does not fit a control frame"
        );
        assert_eq!(
            StreamKind::AttachmentChunks.max_frame_len()
                - kr_protocol::limits::MAX_ATTACHMENT_CHUNK_LEN,
            kr_protocol::limits::MAX_ATTACHMENT_METADATA_LEN
        );
    }

    #[test]
    fn a_host_refusal_keeps_the_category_it_arrived_with() {
        use kr_protocol::error::ErrorCode;

        for (code, expected) in [
            (
                ErrorCode::AttachmentIntegrity,
                ErrorCode::AttachmentIntegrity,
            ),
            (ErrorCode::SourceChanged, ErrorCode::SourceChanged),
            (ErrorCode::QuotaExceeded, ErrorCode::QuotaExceeded),
            (ErrorCode::DraftConflict, ErrorCode::DraftConflict),
            (ErrorCode::PermissionDenied, ErrorCode::PermissionDenied),
            (ErrorCode::StorageUnavailable, ErrorCode::StorageUnavailable),
        ] {
            let error = refusal(&ProtocolError::new(code, "because"));
            assert_eq!(error.code(), expected, "{code:?}");
        }
    }
}
