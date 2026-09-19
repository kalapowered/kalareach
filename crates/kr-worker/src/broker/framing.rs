//! How one connector's frames are wrapped and taken apart again.
//!
//! A connector's qualified table says which of three shapes its protocol uses, and this is the
//! whole of what that means on the wire: a body is wrapped to go out, and a buffer gives back one
//! whole body at a time or says there is not one yet. Nothing here knows what a frame means, which
//! is why [`duplex`](crate::broker::duplex) can read an upstream that is mid-sentence without
//! deciding anything about what it is saying.

use kr_protocol::gateway::NativeFraming;

use crate::broker::error::{BrokerError, Result};
use crate::broker::gateway::MAX_NATIVE_FRAME_BYTES;

/// Reads and writes one connector's frames, as its qualified table describes them.
#[derive(Clone, Copy, Debug)]
pub struct Framing(NativeFraming);

impl Framing {
    /// Frames as this connector does.
    #[must_use]
    pub const fn new(framing: NativeFraming) -> Self {
        Self(framing)
    }

    /// Returns the stable name of this framing, as the registration file publishes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            NativeFraming::JsonLines => "json_lines",
            NativeFraming::LengthPrefixed => "length_prefixed",
            NativeFraming::ContentLength => "content_length",
        }
    }

    /// Wraps one body in the framing this connector uses.
    #[must_use]
    pub fn encode(self, body: &[u8]) -> Vec<u8> {
        match self.0 {
            NativeFraming::JsonLines => {
                let mut framed = Vec::with_capacity(body.len() + 1);
                framed.extend_from_slice(body);
                framed.push(b'\n');
                framed
            }
            NativeFraming::LengthPrefixed => {
                let mut framed = format!("{}\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
            NativeFraming::ContentLength => {
                let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
        }
    }

    /// Takes one whole body out of the buffer, or says there is not one yet.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the buffer holds something this framing
    /// cannot be reading: a declared length that is not a number, or one past the frame bound.
    pub fn decode(self, buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        match self.0 {
            NativeFraming::JsonLines => {
                let Some(end) = buffer.iter().position(|byte| *byte == b'\n') else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let body = buffer.drain(..=end).take(end).collect();
                Ok(Some(body))
            }
            NativeFraming::LengthPrefixed => {
                let Some(end) = buffer.iter().position(|byte| *byte == b'\n') else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let declared = std::str::from_utf8(&buffer[..end])
                    .ok()
                    .and_then(|text| text.trim().parse::<usize>().ok())
                    .ok_or_else(|| {
                        BrokerError::invalid("this frame declares no readable length")
                    })?;
                Self::check_declared(declared)?;
                if buffer.len() < end + 1 + declared {
                    return Ok(None);
                }
                buffer.drain(..=end);
                Ok(Some(buffer.drain(..declared).collect()))
            }
            NativeFraming::ContentLength => {
                let Some(end) = find(buffer, b"\r\n\r\n") else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let headers = std::str::from_utf8(&buffer[..end])
                    .map_err(|_| BrokerError::invalid("this frame's headers are not text"))?;
                let declared = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .ok_or_else(|| {
                        BrokerError::invalid("this frame declares no readable content length")
                    })?;
                Self::check_declared(declared)?;
                if buffer.len() < end + 4 + declared {
                    return Ok(None);
                }
                buffer.drain(..end + 4);
                Ok(Some(buffer.drain(..declared).collect()))
            }
        }
    }

    fn check_partial(held: usize) -> Result<()> {
        if held > MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "a native frame is at most {MAX_NATIVE_FRAME_BYTES} bytes and this one has not \
                 ended after {held}"
            )));
        }
        Ok(())
    }

    fn check_declared(declared: usize) -> Result<()> {
        if declared > MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "this frame declares {declared} bytes and a native frame is at most \
                 {MAX_NATIVE_FRAME_BYTES}"
            )));
        }
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_framing_reads_back_exactly_what_it_wrote() {
        for framing in NativeFraming::ALL {
            let framing = Framing::new(*framing);
            let mut buffer = framing.encode(br#"{"id":1}"#);
            buffer.extend_from_slice(&framing.encode(br#"{"id":2}"#));
            let first = framing
                .decode(&mut buffer)
                .expect("readable")
                .expect("a whole frame");
            let second = framing
                .decode(&mut buffer)
                .expect("readable")
                .expect("a whole frame");
            assert_eq!(first, br#"{"id":1}"#);
            assert_eq!(second, br#"{"id":2}"#);
            assert!(
                framing.decode(&mut buffer).expect("readable").is_none(),
                "and nothing is left over"
            );
        }
    }

    #[test]
    fn a_partial_frame_waits_and_an_unbounded_one_does_not() {
        for framing in NativeFraming::ALL {
            let framing = Framing::new(*framing);
            let whole = framing.encode(br#"{"id":1}"#);
            let mut buffer = whole[..whole.len() - 1].to_vec();
            assert!(
                framing.decode(&mut buffer).expect("readable").is_none(),
                "half a frame is not a frame"
            );
        }
        // A declared length past the bound is refused before anything is allocated for it.
        let framing = Framing::new(NativeFraming::LengthPrefixed);
        let mut buffer = format!("{}\n", MAX_NATIVE_FRAME_BYTES + 1).into_bytes();
        assert!(framing.decode(&mut buffer).is_err());
    }
}
