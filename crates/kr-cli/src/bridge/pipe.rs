//! The bounded frame codec over a bridge's standard streams.
//!
//! The wire is the protocol's own: a four-byte unsigned big-endian length followed by one
//! KR-CBOR-1 object, bounded by section 9's control-frame maximum. The length is checked against
//! that bound *before* any buffer is grown, so a peer cannot make this process reserve memory by
//! claiming a large frame, and an oversized frame is refused rather than truncated: truncating one
//! would hand the destination a prefix of a message somebody else wrote.

use std::io::{Read, Write};

use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, FrameError, StreamKind};
use kr_protocol::identity::BridgeFrame;

/// The codec both ends of a bridge use.
///
/// A bridge carries control frames, so it takes the control stream's bound. The larger attachment
/// bound cannot be selected here, which is the same rule the network transport applies.
#[must_use]
pub const fn codec() -> FrameCodec {
    FrameCodec::new(StreamKind::Control)
}

/// The largest complete frame either end may write, in bytes.
#[must_use]
pub const fn max_frame_len() -> usize {
    StreamKind::Control.max_frame_len()
}

/// What went wrong on a bridge's standard streams.
#[derive(Debug)]
pub enum PipeError {
    /// The peer closed the stream at a frame boundary. An ordinary end.
    Closed,
    /// The stream ended part way through a frame.
    Truncated {
        /// How many payload bytes arrived.
        received: usize,
        /// How many the length prefix declared.
        expected: usize,
    },
    /// The frame is not one this bridge accepts: too large, empty, or not canonical.
    Frame(FrameError),
    /// The underlying stream failed.
    Io(std::io::Error),
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("the bridge peer closed the stream"),
            Self::Truncated { received, expected } => write!(
                formatter,
                "the bridge stream ended after {received} of {expected} payload bytes"
            ),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PipeError {}

impl From<FrameError> for PipeError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<std::io::Error> for PipeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads one frame's payload from `source`.
///
/// The declared length is validated before the payload buffer exists.
///
/// # Errors
///
/// Returns [`PipeError::Closed`] at a clean frame boundary, [`PipeError::Truncated`] when the
/// stream ends inside a frame, and [`PipeError::Frame`] when the declared length is outside the
/// control-frame bound.
pub fn read_payload(source: &mut impl Read) -> Result<Vec<u8>, PipeError> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    let mut filled = 0;
    while filled < FRAME_LENGTH_PREFIX_LEN {
        let read = source.read(&mut prefix[filled..])?;
        if read == 0 {
            return if filled == 0 {
                Err(PipeError::Closed)
            } else {
                Err(PipeError::Truncated {
                    received: filled,
                    expected: FRAME_LENGTH_PREFIX_LEN,
                })
            };
        }
        filled += read;
    }
    // The bound is applied to the declared length, before anything is allocated for it.
    let declared = codec().decode_length(prefix)?;
    let mut payload = vec![0_u8; declared];
    let mut received = 0;
    while received < declared {
        let read = source.read(&mut payload[received..])?;
        if read == 0 {
            return Err(PipeError::Truncated {
                received,
                expected: declared,
            });
        }
        received += read;
    }
    Ok(payload)
}

/// Reads one bridge frame from `source`.
///
/// # Errors
///
/// As [`read_payload`], plus a decoding failure when the payload is not a canonical bridge frame.
pub fn read_frame(source: &mut impl Read) -> Result<BridgeFrame, PipeError> {
    let payload = read_payload(source)?;
    let frame = kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits())
        .map_err(|error| PipeError::Frame(FrameError::Cbor(error)))?;
    Ok(frame)
}

/// Writes one bridge frame to `sink` and flushes it.
///
/// # Errors
///
/// Returns [`PipeError::Frame`] when the encoded frame exceeds the control-frame bound, which is a
/// refusal rather than a truncation, and [`PipeError::Io`] when the stream fails.
pub fn write_frame(sink: &mut impl Write, frame: &BridgeFrame) -> Result<(), PipeError> {
    let bytes = codec().encode_message(frame)?;
    sink.write_all(&bytes)?;
    sink.flush()?;
    Ok(())
}

/// Wraps an already-encoded protocol payload in a bridge frame and writes it.
///
/// The payload arrived from a local connection already bounded by the same maximum, and is carried
/// unchanged: re-encoding it would risk changing the bytes a digest was taken over.
///
/// # Errors
///
/// As [`write_frame`].
pub fn write_carried_payload(sink: &mut impl Write, payload: &[u8]) -> Result<(), PipeError> {
    let frame: kr_protocol::envelope::ControlFrame =
        kr_cbor::from_canonical_slice(payload, &StreamKind::Control.cbor_limits())
            .map_err(|error| PipeError::Frame(FrameError::Cbor(error)))?;
    write_frame(sink, &BridgeFrame::Control(Box::new(frame)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::error::{ErrorCode, ProtocolError};

    fn refusal() -> BridgeFrame {
        BridgeFrame::Refused(ProtocolError::new(ErrorCode::PermissionDenied, "no"))
    }

    #[test]
    fn a_frame_written_here_is_read_back_whole() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &refusal()).expect("writes");
        let decoded = read_frame(&mut buffer.as_slice()).expect("reads");
        assert_eq!(decoded, refusal());
    }

    #[test]
    fn a_declared_length_past_the_bound_is_refused_before_anything_is_allocated() {
        // One byte past the control-frame payload maximum. Nothing is allocated for it: the
        // refusal comes from the length prefix alone.
        let declared = u32::try_from(StreamKind::Control.max_payload_len() + 1).expect("fits");
        let mut stream: Vec<u8> = declared.to_be_bytes().to_vec();
        stream.push(0);
        let error = read_payload(&mut stream.as_slice()).expect_err("a refusal");
        assert!(
            matches!(
                error,
                PipeError::Frame(FrameError::PayloadTooLarge { limit, .. })
                    if limit == StreamKind::Control.max_payload_len()
            ),
            "{error}"
        );
    }

    #[test]
    fn a_zero_length_frame_is_refused() {
        let stream = 0_u32.to_be_bytes().to_vec();
        let error = read_payload(&mut stream.as_slice()).expect_err("a refusal");
        assert!(matches!(error, PipeError::Frame(FrameError::EmptyPayload)));
    }

    #[test]
    fn a_stream_that_ends_inside_a_frame_is_a_truncation_rather_than_a_short_read() {
        let mut stream = 8_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[1, 2, 3]);
        let error = read_payload(&mut stream.as_slice()).expect_err("a refusal");
        assert!(
            matches!(
                error,
                PipeError::Truncated {
                    received: 3,
                    expected: 8
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_clean_end_at_a_boundary_is_the_peer_going_away() {
        let error = read_payload(&mut [].as_slice()).expect_err("an end");
        assert!(matches!(error, PipeError::Closed));
    }

    #[test]
    fn a_carried_payload_reaches_the_other_side_byte_for_byte() {
        use kr_protocol::envelope::{ControlEvent, ControlFrame};

        let original = ControlFrame::Event(ControlEvent::Keepalive);
        let payload = kr_cbor::to_canonical_vec(&original).expect("encodes");
        let mut buffer = Vec::new();
        write_carried_payload(&mut buffer, &payload).expect("writes");
        match read_frame(&mut buffer.as_slice()).expect("reads") {
            BridgeFrame::Control(carried) => {
                assert_eq!(*carried, original);
                assert_eq!(
                    kr_cbor::to_canonical_vec(&*carried).expect("encodes"),
                    payload
                );
            }
            other => panic!("expected a carried frame, got {other:?}"),
        }
    }
}
