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
    /// The bound in force: the stream kind's ceiling, lowered to whatever the peer negotiated.
    max_payload: usize,
    /// Set while a write is in progress. A write that never completed left part of a frame on the
    /// stream, so the stream can carry nothing more.
    interrupted: bool,
}

impl FrameWriter {
    /// Wraps a send stream for one stream kind.
    #[must_use]
    pub fn new(stream: SendStream, kind: StreamKind) -> Self {
        let codec = FrameCodec::new(kind);
        Self {
            stream,
            codec,
            max_payload: codec.max_payload_len(),
            interrupted: false,
        }
    }

    /// Lowers the bound to what the peer said it could receive.
    ///
    /// The stream kind's ceiling still applies: a negotiated value above it is ignored, because
    /// the kind's bound is part of the wire contract and not negotiable upwards.
    #[must_use]
    pub fn with_max_payload(mut self, negotiated: usize) -> Self {
        self.max_payload = self.codec.max_payload_len().min(negotiated);
        self
    }

    /// Returns the bound in force.
    #[must_use]
    pub const fn max_payload(&self) -> usize {
        self.max_payload
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

    /// Returns the send priority the connection is using for this stream, or `None` once the
    /// stream is closed and has none.
    ///
    /// This reads what was installed rather than what was asked for, which is what makes the
    /// scheduler's decision observable: a stream whose priority was never applied answers the
    /// connection's default of zero.
    #[must_use]
    pub fn priority(&self) -> Option<i32> {
        self.stream.priority().ok()
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
        self.write_framed(&length.to_be_bytes(), &encoded).await
    }

    /// Serialises and writes one message.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the message exceeds this stream kind's bound, and a stream
    /// error when the write fails.
    pub async fn write_message<T: Serialize + ?Sized>(&mut self, message: &T) -> Result<()> {
        let payload = kr_cbor::to_canonical_vec_within(
            message,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(self.max_payload),
        )
        .map_err(FrameError::Cbor)?;
        self.write_payload(&payload).await
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
        // A zero length is how the peer's decoder is told a frame is malformed, so a frame that
        // carries nothing is refused here rather than sent and rejected on arrival. Refusing it
        // before the write keeps a caller's mistake a local error instead of a damaged stream.
        if payload.is_empty() {
            return Err(FrameError::EmptyPayload.into());
        }
        if payload.len() > self.max_payload {
            return Err(FrameError::PayloadTooLarge {
                len: payload.len(),
                limit: self.max_payload,
            }
            .into());
        }
        // The prefix and the payload are written as they are, rather than copied into a third
        // buffer. A frame the caller already holds is not duplicated to be sent.
        let length = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge {
            len: payload.len(),
            limit: self.max_payload,
        })?;
        self.write_framed(&length.to_be_bytes(), payload).await
    }

    /// Writes a complete frame, refusing to continue a stream a cancelled write left in pieces.
    ///
    /// `SendStream::write_all` is not cancellation safe: a caller that drops the future part way
    /// through leaves a prefix of one frame on the stream, and the next frame written after it
    /// would be read as the rest of that one. The flag below is set before the write and cleared
    /// only when it finishes, so an interrupted stream is reset rather than silently corrupted.
    /// Writes one frame's prefix and payload, in that order and as one unit.
    async fn write_framed(&mut self, prefix: &[u8], payload: &[u8]) -> Result<()> {
        if self.interrupted {
            self.reset();
            return Err(TransportError::Stream(
                "a cancelled write left this stream incomplete".to_owned(),
            ));
        }
        self.interrupted = true;
        let mut outcome = self
            .stream
            .write_all(prefix)
            .await
            .map_err(|error| TransportError::Stream(error.to_string()));
        if outcome.is_ok() {
            outcome = self
                .stream
                .write_all(payload)
                .await
                .map_err(|error| TransportError::Stream(error.to_string()));
        }
        self.interrupted = false;
        outcome
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

    /// Finishes the stream and waits for the peer to acknowledge what was written.
    ///
    /// A refusal is the last thing a connection says before it goes away, and a connection that is
    /// closed the instant after a write can discard that write. Waiting for the acknowledgement,
    /// bounded so a silent peer cannot hold the host, is what makes the refusal arrive.
    pub async fn finish_and_flush(&mut self, within: std::time::Duration) {
        if self.stream.finish().is_err() {
            return;
        }
        let _ = tokio::time::timeout(within, self.stream.stopped()).await;
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
    /// The bound in force: the stream kind's ceiling, lowered to whatever this side declared.
    max_payload: usize,
    /// Set while a read is in progress. A read that never completed consumed part of a frame, so
    /// the byte after it is not a length prefix and the stream can carry nothing more.
    interrupted: bool,
}

impl FrameReader {
    /// Wraps a receive stream for one stream kind.
    #[must_use]
    pub fn new(stream: RecvStream, kind: StreamKind) -> Self {
        let codec = FrameCodec::new(kind);
        Self {
            stream,
            codec,
            max_payload: codec.max_payload_len(),
            interrupted: false,
        }
    }

    /// Lowers the bound to what this side declared it could receive.
    ///
    /// The stream kind's ceiling still applies. A peer that declares a larger frame than the
    /// negotiated limit is refused before the payload is allocated.
    #[must_use]
    pub fn with_max_payload(mut self, negotiated: usize) -> Self {
        self.max_payload = self.codec.max_payload_len().min(negotiated);
        self
    }

    /// Returns the bound in force.
    #[must_use]
    pub const fn max_payload(&self) -> usize {
        self.max_payload
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
        let codec = FrameCodec::new(kind);
        Self {
            stream: self.stream,
            codec,
            max_payload: codec.max_payload_len(),
            interrupted: self.interrupted,
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
        self.read_message_within(self.max_payload).await
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
        self.read_payload_within(self.max_payload).await
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
        // `RecvStream::read_exact` is not cancellation safe: a caller that drops the future part
        // way through has consumed bytes from the middle of a frame, and the next read would treat
        // the remainder as a length prefix. The flag is set before the first await and cleared only
        // when a whole frame has been read, so an interrupted reader refuses to carry on.
        if self.interrupted {
            self.stop();
            return Err(TransportError::Stream(
                "this stream stopped part way through a frame".to_owned(),
            ));
        }
        self.interrupted = true;
        let outcome = self.read_one(limit).await;
        // The flag is cleared only by a complete frame or a clean end of stream. An error can have
        // consumed a length prefix without its body — a frame past the bound is the ordinary case —
        // and the next read would treat that body as another prefix.
        if outcome.is_ok() {
            self.interrupted = false;
        }
        outcome
    }

    async fn read_one(&mut self, limit: usize) -> Result<Option<Vec<u8>>> {
        let mut prefix = [0u8; FRAME_LENGTH_PREFIX_LEN];
        match self.stream.read_exact(&mut prefix).await {
            Ok(()) => {}
            Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(error) => return Err(TransportError::Stream(error.to_string())),
        }
        let declared = self.codec.decode_length(prefix)?;
        let limit = limit.min(self.max_payload);
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
