//! Reading and writing typed frames on a local connection.
//!
//! The wire format is the one in section 23: a four-byte unsigned big-endian length followed by
//! one KR-CBOR-1 object. The length is validated against the stream kind's bound before the
//! payload buffer is grown, so a peer cannot make the host reserve a gigabyte by claiming one.
//!
//! Reading and writing are separate halves on purpose. A worker publishes output while a client is
//! still sending input, and one task owning both directions would serialise them.

#[cfg(windows)]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(windows)]
use std::task::{Context, Poll};

use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, StreamKind};
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(windows)]
use tokio::io::AsyncWrite as _;
use tokio::io::{AsyncReadExt as _, ReadHalf, WriteHalf};

use crate::endpoint::Connection;
use crate::error::{IpcError, Result};

/// Splits a connection into a frame reader and a frame writer.
#[must_use]
pub fn split(connection: Connection, kind: StreamKind) -> (FrameReader, FrameWriter) {
    let writable = Writable::of(&connection);
    // A descriptor of this connection's own to write through. The bytes go to the same socket, and
    // the attempt is the kernel's own answer rather than a runtime's record of what it last saw:
    // what decides whether a frame may be sent is a lock this writer is holding, and a write that
    // consulted a reactor's bookkeeping instead could be told to wait by something the socket does
    // not know about.
    #[cfg(unix)]
    let descriptor = connection.writability().ok();
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
            writable,
            #[cfg(unix)]
            descriptor,
        },
    )
}

/// What a write attempt that refuses to wait achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wrote {
    /// Every byte of the frame is with the peer.
    Complete,
    /// The socket would take no more of it. What is left is retained, and a later attempt
    /// continues it; [`Writable::ready`] is how a caller waits for that moment without holding
    /// whatever else it owns.
    Blocked,
}

/// A handle on a connection's writability, separate from the writer itself.
///
/// Waiting for room and deciding whether bytes may still be sent are two different things, and a
/// caller that has to do both wants them apart: the waiting happens here, outside whatever lock
/// makes the decision, and the writing happens inside it without ever waiting. A handle is cheap
/// to clone and several may wait at once.
#[derive(Clone, Debug)]
pub struct Writable(Arc<Readiness>);

impl Writable {
    fn of(connection: &Connection) -> Self {
        Self(Arc::new(Readiness::of(connection)))
    }

    /// Waits until the connection will probably take more bytes.
    ///
    /// "Probably" is the honest word: readiness is the kernel's answer at the moment it was asked,
    /// and the attempt that follows is what settles it.
    ///
    /// # Errors
    ///
    /// Returns a socket failure when the connection cannot be waited on at all.
    pub async fn ready(&self) -> Result<()> {
        self.0.ready().await
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct Readiness(Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>);

#[cfg(unix)]
impl Readiness {
    fn of(connection: &Connection) -> Self {
        // A descriptor of this connection's own, so waiting on it borrows nothing the writer
        // holds. A connection this cannot be taken for is one whose writes fail anyway, and the
        // wait below then yields rather than pretending to be readiness.
        Self(connection.writability().ok().and_then(|descriptor| {
            tokio::io::unix::AsyncFd::with_interest(descriptor, tokio::io::Interest::WRITABLE).ok()
        }))
    }

    async fn ready(&self) -> Result<()> {
        let Some(descriptor) = self.0.as_ref() else {
            tokio::task::yield_now().await;
            return Ok(());
        };
        let mut guard = descriptor
            .writable()
            .await
            .map_err(|error| IpcError::socket("wait for the connection", error))?;
        // Cleared here rather than after a write, because the write happens somewhere this cannot
        // see: the next wait asks the kernel again instead of trusting a readiness nobody consumed.
        guard.clear_ready();
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct Readiness;

#[cfg(windows)]
impl Readiness {
    const fn of(_connection: &Connection) -> Self {
        Self
    }

    /// Waits a moment and lets the caller try again.
    ///
    /// There is no readiness of this connection's own to wait on that the writer can hold while the
    /// reader holds the other half: a pipe object is one object, and a second one over the same
    /// pipe would take bytes the reader needs. So a writer that was refused comes back shortly
    /// rather than spinning. The attempt itself is the same on both platforms, and it is the
    /// attempt that never waits.
    async fn ready(&self) -> Result<()> {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        Ok(())
    }
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
    /// The connection's write half, which keeps this end of it open for as long as the writer
    /// lives, and on Windows is what the attempt writes through. On a platform with descriptors the
    /// bytes go through [`FrameWriter::descriptor`] instead, because the socket's own answer is
    /// what the boundary this writer sits inside needs rather than a runtime's record of what it
    /// last saw.
    #[cfg_attr(
        unix,
        expect(dead_code, reason = "it owns the half rather than writing through it")
    )]
    half: WriteHalf<Connection>,
    codec: FrameCodec,
    pending: Vec<u8>,
    sent: usize,
    writable: Writable,
    /// This connection's own descriptor, which is what the attempt writes through.
    #[cfg(unix)]
    descriptor: Option<std::os::fd::OwnedFd>,
}

impl FrameWriter {
    /// Returns whether a frame has been partly written and not finished.
    ///
    /// A write that was cancelled part way left its beginning with the peer, so the stream can only
    /// continue by finishing that frame. A caller that no longer stands behind what was cut in half
    /// asks this before it writes anything else, and ends the connection instead: the alternative
    /// is pushing out the rest of something it has decided not to send.
    #[must_use]
    pub const fn is_mid_frame(&self) -> bool {
        self.sent < self.pending.len()
    }

    /// Returns a handle on this connection's writability.
    ///
    /// It is what a caller waits on while it is *not* holding this writer, so that the decision to
    /// send and the sending itself can be one step that never waits.
    #[must_use]
    pub fn writable(&self) -> Writable {
        self.writable.clone()
    }

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

    /// Writes an already framed buffer, waiting for the peer as often as it takes.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerClosed`] when the peer is gone, or a socket failure.
    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        let mut outcome = self.begin_frame(frame)?;
        while outcome == Wrote::Blocked {
            let writable = self.writable.clone();
            writable.ready().await?;
            outcome = self.resume_frame()?;
        }
        Ok(())
    }

    /// Offers a frame to the peer without waiting for it.
    ///
    /// A frame the socket would not take whole is retained and continued by [`resume_frame`],
    /// which is what lets the decision to send it be made under a lock that is never held across a
    /// wait. Starting a frame while another is half written is refused rather than interleaved.
    ///
    /// [`resume_frame`]: Self::resume_frame
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerClosed`] when the peer is gone, or a socket failure.
    pub fn begin_frame(&mut self, frame: &[u8]) -> Result<Wrote> {
        if self.is_mid_frame() {
            return Err(IpcError::socket(
                "write",
                std::io::Error::other("a frame is already part way to the peer"),
            ));
        }
        self.pending.clear();
        self.pending.extend_from_slice(frame);
        self.sent = 0;
        self.attempt()
    }

    /// Offers the rest of a retained frame to the peer without waiting for it.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerClosed`] when the peer is gone, or a socket failure.
    pub fn resume_frame(&mut self) -> Result<Wrote> {
        self.attempt()
    }

    /// Writes what it can and stops at the first byte the socket will not take.
    ///
    /// What this reports is the socket's own answer now. Waiting for a different answer is
    /// [`Writable::ready`]'s job, somewhere this writer is not held.
    #[cfg(unix)]
    fn attempt(&mut self) -> Result<Wrote> {
        let Some(descriptor) = self.descriptor.as_ref() else {
            return Err(IpcError::PeerClosed);
        };
        while self.sent < self.pending.len() {
            match rustix::io::write(descriptor, &self.pending[self.sent..]) {
                Ok(0) => return Err(IpcError::PeerClosed),
                Ok(written) => self.sent += written,
                Err(rustix::io::Errno::AGAIN) => return Ok(Wrote::Blocked),
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::PIPE | rustix::io::Errno::CONNRESET) => {
                    return Err(IpcError::PeerClosed);
                }
                Err(error) => return Err(IpcError::socket("write", error.into())),
            }
        }
        Ok(Wrote::Complete)
    }

    /// Writes what it can and stops at the first byte the pipe will not take.
    ///
    /// The attempt is made on the connection's own write half, with a waker nothing wakes: what
    /// this reports is the pipe's answer now, and waiting for a different answer is
    /// [`Writable::ready`]'s job. It is *this* object rather than a duplicate of the handle on
    /// purpose. A duplicate adopted by the runtime would be a second pipe object over one pipe, and
    /// registering one starts a read of its own: the bytes it took would be bytes
    /// [`FrameReader`] never sees. One object reads, writes and reports readiness, or the stream
    /// loses frames.
    #[cfg(windows)]
    fn attempt(&mut self) -> Result<Wrote> {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.half).poll_write(&mut context, &self.pending[self.sent..]) {
                Poll::Pending => return Ok(Wrote::Blocked),
                Poll::Ready(Ok(0)) => return Err(IpcError::PeerClosed),
                Poll::Ready(Ok(written)) => self.sent += written,
                Poll::Ready(Err(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Err(IpcError::PeerClosed);
                }
                Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(Wrote::Blocked);
                }
                Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Poll::Ready(Err(error)) => return Err(IpcError::socket("write", error)),
            }
        }
        // A flush the pipe defers changes nothing here: the bytes are with the operating system,
        // which is what delivery means on a local connection.
        let _ = Pin::new(&mut self.half).poll_flush(&mut context);
        Ok(Wrote::Complete)
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
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::envelope::{ParamsValue, Request};
    use kr_protocol::ids::RequestId;
    use kr_protocol::method::{Method, MethodVersion};

    use super::*;
    use crate::paths::Endpoint;
    use crate::testing::TempHost;

    fn request(id: u64) -> ControlFrame {
        ControlFrame::Request(Request {
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
            let received: ControlFrame = reader.read_message().await.expect("reads");
            writer.write_message(&received).await.expect("writes");
            received
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(9)).await.expect("writes");
        let echoed: ControlFrame = reader.read_message().await.expect("reads");
        assert_eq!(echoed, request(9));
        assert_eq!(server.await.expect("server task"), request(9));
    }

    #[tokio::test]
    async fn a_peer_that_stops_reading_blocks_the_attempt_rather_than_holding_the_writer() {
        // What a boundary needs: an attempt that answers now, whatever the peer is doing, and a
        // wait that happens somewhere else. A peer that reads nothing fills the socket, and the
        // attempt says so instead of staying inside the write until the peer comes back.
        let (endpoint, listener, _host) = pair();
        let server = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accepts");
            // Held, not read from, until the test says so.
            let (reader, _writer) = split(connection, StreamKind::Control);
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(reader);
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (_reader, mut writer) = split(client, StreamKind::Control);

        // One frame after another, without waiting for any of them, until the socket is full.
        let frame = FrameWriter::encode(StreamKind::Control, &request(1)).expect("encodes");
        let mut blocked = None;
        for _ in 0..4096 {
            match writer.begin_frame(&frame).expect("the peer is still there") {
                Wrote::Complete => {}
                Wrote::Blocked => {
                    blocked = Some(());
                    break;
                }
            }
        }
        assert!(
            blocked.is_some(),
            "the attempt reports a socket that would take no more rather than waiting for it"
        );
        assert!(
            writer.is_mid_frame(),
            "and what it could not send is retained rather than lost"
        );
        assert!(
            writer.begin_frame(&frame).is_err(),
            "a new frame is refused while one is part way to the peer"
        );
        // And the waiting is real: a socket with no room does not report readiness, so a caller
        // that waits here parks rather than spinning through attempt after attempt.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                writer.writable().ready()
            )
            .await
            .is_err(),
            "a full socket keeps the waiter waiting"
        );
        server.abort();
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
            let first: ControlFrame = reader.read_message().await.expect("reads the frame");
            writer.write_message(&first).await.expect("acknowledges");
            reader.read_payload().await.expect_err("reports truncation")
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(1)).await.expect("writes");
        let _acknowledged: ControlFrame = reader.read_message().await.expect("reads the reply");
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
            let first: ControlFrame = reader.read_message().await.expect("reads the frame");
            // The reply tells the client that this end has accepted and authenticated it, so the
            // close below happens after authentication rather than racing it.
            writer.write_message(&first).await.expect("acknowledges");
            reader.read_payload().await.expect_err("reports closure")
        });
        let client = Connection::connect(&endpoint).await.expect("connects");
        let (mut reader, mut writer) = split(client, StreamKind::Control);
        writer.write_message(&request(1)).await.expect("writes");
        let _acknowledged: ControlFrame = reader.read_message().await.expect("reads the reply");
        // Both halves must go: the stream stays open while either one is alive.
        drop((reader, writer));
        assert!(matches!(
            server.await.expect("server task"),
            IpcError::PeerClosed
        ));
    }
}
