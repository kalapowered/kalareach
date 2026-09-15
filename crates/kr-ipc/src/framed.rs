//! Reading and writing typed frames on a local connection.
//!
//! The wire format is the one in section 23: a four-byte unsigned big-endian length followed by
//! one KR-CBOR-1 object. The length is validated against the stream kind's bound before the
//! payload buffer is grown, so a peer cannot make the host reserve a gigabyte by claiming one.
//!
//! Reading and writing are separate halves on purpose. A worker publishes output while a client is
//! still sending input, and one task owning both directions would serialise them.

use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, StreamKind};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, ReadHalf, WriteHalf};

use crate::endpoint::Connection;
use crate::error::{IpcError, Result};

/// Splits a connection into a frame reader and a frame writer.
#[must_use]
pub fn split(connection: Connection, kind: StreamKind) -> (FrameReader, FrameWriter) {
    let (reader, writer) = tokio::io::split(connection);
    (
        FrameReader {
            half: reader,
            codec: FrameCodec::new(kind),
            prefix: [0; FRAME_LENGTH_PREFIX_LEN],
            prefix_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            declared: None,
        },
        FrameWriter {
            half: writer,
            codec: FrameCodec::new(kind),
            pending: Vec::new(),
            sent: 0,
        },
    )
}

/// The reading half of a framed connection.
///
/// The reader keeps its own buffer and its own position in the current frame, so a read whose
/// future is dropped part way through — a `select!` arm that lost, a task that was cancelled —
/// resumes from where it stopped instead of restarting mid-frame against a stream that has already
/// moved on.
#[derive(Debug)]
pub struct FrameReader {
    half: ReadHalf<Connection>,
    codec: FrameCodec,
    prefix: [u8; FRAME_LENGTH_PREFIX_LEN],
    prefix_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
    declared: Option<usize>,
}

impl FrameReader {
    /// Reads one frame's payload.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerClosed`] at a clean frame boundary, [`IpcError::TruncatedFrame`]
    /// when the stream ends part way through a frame, or a framing failure when the declared
    /// length is out of bounds.
    pub async fn read_payload(&mut self) -> Result<Vec<u8>> {
        while self.declared.is_none() {
            let read = self
                .half
                .read(&mut self.prefix[self.prefix_filled..])
                .await
                .map_err(|error| IpcError::socket("read", error))?;
            if read == 0 {
                return if self.prefix_filled == 0 {
                    // A clean end at a frame boundary is the peer going away, not a broken frame.
                    Err(IpcError::PeerClosed)
                } else {
                    Err(IpcError::TruncatedFrame {
                        received: self.prefix_filled,
                        expected: FRAME_LENGTH_PREFIX_LEN,
                    })
                };
            }
            self.prefix_filled += read;
            if self.prefix_filled == FRAME_LENGTH_PREFIX_LEN {
                // The bound is checked here, before the buffer is grown.
                let declared = self.codec.decode_length(self.prefix)?;
                self.payload = vec![0_u8; declared];
                self.payload_filled = 0;
                self.declared = Some(declared);
            }
        }
        let declared = self.declared.unwrap_or_default();
        while self.payload_filled < declared {
            let read = self
                .half
                .read(&mut self.payload[self.payload_filled..])
                .await
                .map_err(|error| IpcError::socket("read", error))?;
            if read == 0 {
                return Err(IpcError::TruncatedFrame {
                    received: self.payload_filled,
                    expected: declared,
                });
            }
            self.payload_filled += read;
        }
        self.prefix_filled = 0;
        self.payload_filled = 0;
        self.declared = None;
        Ok(std::mem::take(&mut self.payload))
    }

    /// Reads one frame and parses it as `T`.
    ///
    /// # Errors
    ///
    /// Returns a framing failure, or a CBOR failure when the payload is not a canonical `T`.
    pub async fn read_message<T: DeserializeOwned + Serialize>(&mut self) -> Result<T> {
        let payload = self.read_payload().await?;
        let limits = self.codec.kind().cbor_limits();
        kr_cbor::from_canonical_slice(&payload, &limits)
            .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))
    }
}

/// The writing half of a framed connection.
///
/// Like the reader, the writer keeps the bytes it has not yet sent. A cancelled write therefore
/// leaves a partial frame pending rather than lost, and the next call finishes it.
#[derive(Debug)]
pub struct FrameWriter {
    half: WriteHalf<Connection>,
    codec: FrameCodec,
    pending: Vec<u8>,
    sent: usize,
}

impl FrameWriter {
    /// Serialises a message and writes it as one frame.
    ///
    /// # Errors
    ///
    /// Returns a framing failure when the encoded message exceeds the stream's bound, or a socket
    /// failure when the peer is gone.
    pub async fn write_message<T: Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        let frame = self.codec.encode_message(message)?;
        self.write_frame(&frame).await
    }

    /// Writes an already framed buffer.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerClosed`] when the peer is gone, or a socket failure.
    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.sent < self.pending.len() {
            // A previous write was cancelled part way through. Finishing it first keeps the stream
            // well formed; the frame the caller just supplied is written after it, never instead
            // of it.
            self.drain().await?;
        }
        self.pending.clear();
        self.pending.extend_from_slice(frame);
        self.sent = 0;
        self.drain().await?;
        self.half
            .flush()
            .await
            .map_err(|error| IpcError::socket("flush", error))
    }

    async fn drain(&mut self) -> Result<()> {
        while self.sent < self.pending.len() {
            match self.half.write(&self.pending[self.sent..]).await {
                Ok(0) => return Err(IpcError::PeerClosed),
                Ok(written) => self.sent += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Err(IpcError::PeerClosed);
                }
                Err(error) => return Err(IpcError::socket("write", error)),
            }
        }
        Ok(())
    }

    /// Encodes a message into a frame without writing it.
    ///
    /// Fan-out encodes once and writes the same bytes to every subscriber.
    ///
    /// # Errors
    ///
    /// Returns a framing failure when the encoded message exceeds the stream's bound.
    pub fn encode<T: Serialize + ?Sized>(kind: StreamKind, message: &T) -> Result<Vec<u8>> {
        FrameCodec::new(kind)
            .encode_message(message)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::envelope::{ParamsValue, Request};
    use kr_protocol::ids::RequestId;
    use kr_protocol::local::ControlMessage;
    use kr_protocol::method::{Method, MethodVersion};

    use super::*;
    use crate::paths::Endpoint;
    use crate::testing::TempHost;

    fn request(id: u64) -> ControlMessage {
        ControlMessage::Request(Request {
            request_id: RequestId::new(id),
            method: Method::SessionList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        })
    }

    fn pair() -> (Endpoint, crate::endpoint::Listener, TempHost) {
        let host = TempHost::create();
        let endpoint = host.environment().controller_endpoint().expect("endpoint");
        let listener = crate::endpoint::Listener::bind(&endpoint).expect("binds");
        (endpoint, listener, host)
    }

    #[tokio::test]
    async fn frames_round_trip_and_the_peer_is_authenticated() {
        let (endpoint, listener, _host) = pair();
        let server = tokio::spawn(async move {
            let (connection, peer) = listener.accept().await.expect("accepts");
            assert_eq!(peer.uid, crate::paths::current_uid());
            assert!(peer.pid.is_some(), "the platform reports the peer process");
            let (mut reader, mut writer) = split(connection, StreamKind::Control);
            let received: ControlMessage = reader.read_message().await.expect("reads");
            writer.write_message(&received).await.expect("writes");
            received
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(9)).await.expect("writes");
        let echoed: ControlMessage = reader.read_message().await.expect("reads");
        assert_eq!(echoed, request(9));
        assert_eq!(server.await.expect("server task"), request(9));
    }

    #[tokio::test]
    async fn an_over_long_declared_length_is_refused_before_the_buffer_exists() {
        let (endpoint, listener, _host) = pair();
        let server = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accepts");
            let (mut reader, _writer) = split(connection, StreamKind::TerminalInput);
            reader.read_payload().await.expect_err("refuses")
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (_reader, mut writer) = split(client, StreamKind::TerminalInput);
        // One byte over the 64 KiB input frame bound, counting the prefix.
        let declared =
            u32::try_from(StreamKind::TerminalInput.max_payload_len() + 1).expect("fits");
        writer
            .write_frame(&declared.to_be_bytes())
            .await
            .expect("writes the prefix");
        let error = server.await.expect("server task");
        assert!(matches!(
            error,
            IpcError::Frame(kr_protocol::frame::FrameError::PayloadTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn a_stream_that_ends_mid_frame_is_truncated_rather_than_closed() {
        let (endpoint, listener, _host) = pair();
        let server = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accepts");
            let (mut reader, mut writer) = split(connection, StreamKind::Control);
            let first: ControlMessage = reader.read_message().await.expect("reads the frame");
            writer.write_message(&first).await.expect("acknowledges");
            reader.read_payload().await.expect_err("reports truncation")
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(1)).await.expect("writes");
        let _acknowledged: ControlMessage = reader.read_message().await.expect("reads the reply");
        // Two bytes of a four-byte length prefix, then the connection goes.
        writer
            .write_frame(&[0, 0])
            .await
            .expect("writes a fragment");
        drop((reader, writer));
        assert!(matches!(
            server.await.expect("server task"),
            IpcError::TruncatedFrame {
                received: 2,
                expected: 4
            }
        ));
    }

    #[tokio::test]
    async fn a_closed_peer_is_reported_as_closed_rather_than_as_a_broken_frame() {
        let (endpoint, listener, _host) = pair();
        let server = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accepts");
            let (mut reader, mut writer) = split(connection, StreamKind::Control);
            let first: ControlMessage = reader.read_message().await.expect("reads the frame");
            // The reply tells the client that this end has accepted and authenticated it, so the
            // close below happens after authentication rather than racing it.
            writer.write_message(&first).await.expect("acknowledges");
            reader.read_payload().await.expect_err("reports closure")
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(1)).await.expect("writes");
        let _acknowledged: ControlMessage = reader.read_message().await.expect("reads the reply");
        // Both halves must go: the stream stays open while either one is alive.
        drop((reader, writer));
        assert!(matches!(
            server.await.expect("server task"),
            IpcError::PeerClosed
        ));
    }
}
