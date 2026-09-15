//! Length-delimited KR-CBOR-1 frames over a QUIC stream.
//!
//! The framing rule is in `kr-protocol`: a four-byte unsigned big-endian length followed by one
//! KR-CBOR-1 object, with the length validated against the stream kind's bound before the payload
//! is allocated. This module is the asynchronous half of that: it reads the prefix, hands it to
//! [`kr_protocol::frame::FrameCodec`], and only then reserves a buffer. A peer that declares a
//! 4 GiB frame on an input stream is refused having cost four bytes of reading.
//!
//! Each stream also begins with its bounded 1 KiB header, which travels in the same shape so the
//! reader never has a second parsing rule to get right.

use iroh::endpoint::{RecvStream, SendStream};
use kr_protocol::frame::{
    FRAME_LENGTH_PREFIX_LEN, FrameCodec, FrameError, StreamHeader, StreamKind,
};
use kr_protocol::limits::MAX_STREAM_HEADER_LEN;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Result, TransportError};

/// Writes frames of one stream kind.
#[derive(Debug)]
pub struct FrameWriter {
    stream: SendStream,
    codec: FrameCodec,
}

impl FrameWriter {
    /// Wraps a send stream for one stream kind.
    #[must_use]
    pub fn new(stream: SendStream, kind: StreamKind) -> Self {
        Self {
            stream,
            codec: FrameCodec::new(kind),
        }
    }

    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(&self) -> StreamKind {
        self.codec.kind()
    }

    /// Sets this stream's send priority.
    ///
    /// The scheduler decides the value; see [`crate::scheduler`]. Setting it on a closed stream is
    /// not an error, because a closed stream has nothing left to prioritise.
    pub fn set_priority(&self, priority: i32) {
        let _ = self.stream.set_priority(priority);
    }

    /// Writes this stream's bounded header.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the header exceeds 1 KiB, and a stream error when the write
    /// fails.
    pub async fn write_header(&mut self, header: &StreamHeader) -> Result<()> {
        let encoded = header.encode()?;
        let length = u32::try_from(encoded.len()).map_err(|_| FrameError::HeaderTooLarge {
            len: encoded.len(),
            limit: MAX_STREAM_HEADER_LEN,
        })?;
        let mut framed = Vec::with_capacity(FRAME_LENGTH_PREFIX_LEN + encoded.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&encoded);
        self.write_all(&framed).await
    }

    /// Serialises and writes one message.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the message exceeds this stream kind's bound, and a stream
    /// error when the write fails.
    pub async fn write_message<T: Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        let framed = self.codec.encode_message(message)?;
        self.write_all(&framed).await
    }

    /// Frames and writes one already-canonical payload.
    ///
    /// The echo path and any forwarder that moves a frame without interpreting it use this: a
    /// payload that was accepted on the way in does not need re-encoding on the way out.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the payload is empty or exceeds this stream kind's bound, and
    /// a stream error when the write fails.
    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        let framed = self.codec.encode(payload)?;
        self.write_all(&framed).await
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream
            .write_all(bytes)
            .await
            .map_err(|error| TransportError::Stream(error.to_string()))
    }

    /// Finishes the stream, telling the peer no more frames follow.
    ///
    /// # Errors
    ///
    /// Returns a stream error when the stream was already closed by the peer.
    pub fn finish(&mut self) -> Result<()> {
        self.stream
            .finish()
            .map_err(|error| TransportError::Stream(error.to_string()))
    }

    /// Resets the stream, discarding anything still queued.
    ///
    /// This is how a revoked data stream ends: the peer learns the stream is gone rather than
    /// seeing a clean end of data it might mistake for completion.
    pub fn reset(&mut self) {
        let _ = self
            .stream
            .reset(iroh::endpoint::VarInt::from(STREAM_REVOKED));
    }
}

/// The QUIC application error code a revoked stream is reset with.
///
/// Closing or failing the control stream revokes every data stream it authorised; the peer sees
/// this code rather than an ordinary end of stream.
pub const STREAM_REVOKED: u32 = 1;

/// Reads frames of one stream kind.
#[derive(Debug)]
pub struct FrameReader {
    stream: RecvStream,
    codec: FrameCodec,
}

impl FrameReader {
    /// Wraps a receive stream for one stream kind.
    #[must_use]
    pub fn new(stream: RecvStream, kind: StreamKind) -> Self {
        Self {
            stream,
            codec: FrameCodec::new(kind),
        }
    }

    /// Returns the stream kind.
    #[must_use]
    pub const fn kind(&self) -> StreamKind {
        self.codec.kind()
    }

    /// Returns the same stream, read as another kind.
    ///
    /// A stream's kind is declared in its header, so the header itself has to be read before the
    /// kind is known. The reader that read it is rebound here, once, to the kind it declared.
    #[must_use]
    pub fn for_kind(self, kind: StreamKind) -> Self {
        Self {
            stream: self.stream,
            codec: FrameCodec::new(kind),
        }
    }

    /// Returns true when this stream carried QUIC 0-RTT data.
    ///
    /// Version 1 accepts no application mutation in 0-RTT, so every request that arrives here is
    /// classified before it is admitted.
    #[must_use]
    pub fn is_zero_rtt(&self) -> bool {
        self.stream.is_0rtt()
    }

    /// Reads this stream's bounded header.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the declared header exceeds 1 KiB or is not canonical, and a
    /// stream error when the peer ended the stream first.
    pub async fn read_header(&mut self) -> Result<StreamHeader> {
        let declared = self.read_length(MAX_STREAM_HEADER_LEN).await?;
        let mut buffer = vec![0u8; declared];
        self.read_exact(&mut buffer).await?;
        Ok(StreamHeader::decode(&buffer)?)
    }

    /// Reads one frame and deserialises it, or returns `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the declared length exceeds this stream kind's bound or the
    /// payload is not a canonical message of the expected shape.
    pub async fn read_message<T: DeserializeOwned + Serialize>(&mut self) -> Result<Option<T>> {
        let Some(payload) = self.read_payload().await? else {
            return Ok(None);
        };
        let limits = self.codec.kind().cbor_limits();
        let message = kr_cbor::from_canonical_slice(&payload, &limits).map_err(FrameError::Cbor)?;
        Ok(Some(message))
    }

    /// Reads one frame's raw payload, or returns `None` when the peer ended the stream.
    ///
    /// Terminal bytes are not canonical CBOR objects in their own right; they arrive inside a
    /// message. This exists for the parts of the connection that forward a payload without
    /// interpreting it.
    ///
    /// # Errors
    ///
    /// As [`FrameReader::read_message`], without the deserialisation step.
    pub async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        self.read_payload_within(self.codec.max_payload_len()).await
    }

    /// Reads one frame's payload under a bound tighter than the stream kind's own.
    ///
    /// The pre-authorisation pairing surface uses this: its messages are small, and an unpaired
    /// peer has no business making the host reserve a megabyte.
    ///
    /// # Errors
    ///
    /// As [`FrameReader::read_payload`], with `limit` applied as well.
    pub async fn read_payload_within(&mut self, limit: usize) -> Result<Option<Vec<u8>>> {
        let mut prefix = [0u8; FRAME_LENGTH_PREFIX_LEN];
        match self.stream.read_exact(&mut prefix).await {
            Ok(()) => {}
            Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(error) => return Err(TransportError::Stream(error.to_string())),
        }
        let declared = self.codec.decode_length(prefix)?;
        if declared > limit {
            return Err(FrameError::PayloadTooLarge {
                len: declared,
                limit,
            }
            .into());
        }
        let mut payload = vec![0u8; declared];
        self.read_exact(&mut payload).await?;
        Ok(Some(payload))
    }

    /// Reads one bounded frame and deserialises it.
    ///
    /// # Errors
    ///
    /// As [`FrameReader::read_message`], with `limit` applied as well.
    pub async fn read_message_within<T: DeserializeOwned + Serialize>(
        &mut self,
        limit: usize,
    ) -> Result<Option<T>> {
        let Some(payload) = self.read_payload_within(limit).await? else {
            return Ok(None);
        };
        let limits = kr_cbor::Limits::DEFAULT.with_max_message_len(limit);
        let message = kr_cbor::from_canonical_slice(&payload, &limits).map_err(FrameError::Cbor)?;
        Ok(Some(message))
    }

    async fn read_length(&mut self, limit: usize) -> Result<usize> {
        let mut prefix = [0u8; FRAME_LENGTH_PREFIX_LEN];
        self.stream
            .read_exact(&mut prefix)
            .await
            .map_err(|error| TransportError::Stream(error.to_string()))?;
        let declared = u32::from_be_bytes(prefix) as usize;
        if declared == 0 {
            return Err(FrameError::EmptyPayload.into());
        }
        if declared > limit {
            return Err(FrameError::HeaderTooLarge {
                len: declared,
                limit,
            }
            .into());
        }
        Ok(declared)
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        self.stream
            .read_exact(buffer)
            .await
            .map_err(|error| TransportError::Stream(error.to_string()))
    }

    /// Stops the stream, telling the peer this side will read nothing more.
    pub fn stop(&mut self) {
        let _ = self
            .stream
            .stop(iroh::endpoint::VarInt::from(STREAM_REVOKED));
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::frame::{FrameCodec, StreamKind};

    #[test]
    fn a_length_beyond_the_stream_kinds_bound_is_refused_before_allocation() {
        let codec = FrameCodec::new(StreamKind::TerminalInput);
        let declared = u32::MAX.to_be_bytes();
        let error = codec.decode_length(declared).expect_err("a refusal");
        assert!(matches!(
            error,
            kr_protocol::frame::FrameError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn an_attachment_bound_cannot_be_claimed_on_a_control_stream() {
        let attachment = StreamKind::AttachmentChunks.max_payload_len();
        let control = FrameCodec::new(StreamKind::Control);
        let declared = u32::try_from(attachment).expect("the attachment bound fits a u32");
        assert!(control.decode_length(declared.to_be_bytes()).is_err());
    }
}
