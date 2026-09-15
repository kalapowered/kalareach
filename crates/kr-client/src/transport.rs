//! The two ways a client reaches a host.
//!
//! Section 23: local Unix sockets and Windows named pipes carry the same typed frames as a network
//! connection, with local peer authentication instead of a device proof. [`ControlTransport`] is
//! that shared shape, and it is a complete one: send a control frame, read the next control frame,
//! and end the connection. [`crate::session::Session`] is written against the trait and nothing
//! else, so the client's request bookkeeping, cursors and reconnect behaviour are the same whichever
//! way it connected, and an implementation over a local socket needs no change above it.
//!
//! [`NetworkTransport`] is the iroh half: it dials a paired host, performs `hello` and the
//! `kr-connect/1` proofs, and hands back the control stream. The local half is implemented by the
//! IPC crate, which owns the socket, the peer credentials and the runtime directory.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamHeader;
use kr_protocol::hello::{ALPN, ActionWindow, ReceiveLimits};
use kr_protocol::ids::ConnectionId;
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::handshake::{self, LocalIdentity};
use kr_transport::scheduler::{BulkLimits, StreamBudget};
use kr_transport::streams::{DataStream, StreamRegistry};
use tokio::sync::Mutex;

use crate::error::{ClientError, Result};

/// A boxed future, so the transport stays usable behind a trait object.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What a client needs from whichever transport it connected over.
///
/// The trait is narrow on purpose: everything above it works in control frames and data streams,
/// which is all the two transports have in common and all the protocol asks of them.
pub trait ControlTransport: Send + Sync + std::fmt::Debug {
    /// Returns the connection identity the host allocated.
    fn connection_id(&self) -> ConnectionId;

    /// Returns the limits in force on this connection.
    fn limits(&self) -> ReceiveLimits;

    /// Returns the action window the connection started with.
    fn initial_action_window(&self) -> ActionWindow;

    /// Sends one control frame.
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()>;

    /// Reads the next control frame, or `None` when the peer ended the stream.
    ///
    /// Exactly one task reads a connection. The second caller is refused rather than given a second
    /// reader, because two readers on one stream would interleave frames.
    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>>;

    /// Opens a data stream, sending its bounded header first.
    fn open_stream(&self, header: StreamHeader) -> TransportFuture<'_, DataStream>;

    /// Accepts a data stream the host opened.
    fn accept_stream(&self) -> TransportFuture<'_, DataStream>;

    /// Revokes every data stream, which is what the end of the control stream means.
    fn revoke_streams(&self);

    /// Ends the connection.
    fn close(&self);
}

/// A connection to a paired host over iroh.
#[derive(Debug)]
pub struct NetworkTransport {
    connection: Connection,
    connection_id: ConnectionId,
    limits: ReceiveLimits,
    initial_action_window: ActionWindow,
    writer: Arc<Mutex<FrameWriter>>,
    reader: Mutex<Option<FrameReader>>,
    streams: Arc<StreamRegistry>,
}

impl NetworkTransport {
    /// Dials a paired host and completes the handshake.
    ///
    /// The host record is the client's own paired record of the host, not something the host sends:
    /// the proof is checked against what this device already knows.
    ///
    /// # Errors
    ///
    /// Returns a transport failure, including the host's refusal when the handshake fails.
    pub async fn connect(
        endpoint: &Endpoint,
        host_addr: impl Into<EndpointAddr>,
        identity: &LocalIdentity,
        host_record: &PairedPeer,
        bulk_limits: BulkLimits,
    ) -> Result<Self> {
        let connection = endpoint
            .connect(host_addr, ALPN)
            .await
            .map_err(|error| kr_transport::TransportError::Connect(error.to_string()))?;
        let authorised = handshake::connect(&connection, identity, host_record).await?;
        let streams = Arc::new(StreamRegistry::new(
            authorised.connection_id,
            Arc::new(StreamBudget::new(bulk_limits)),
            None,
        ));
        Ok(Self {
            connection,
            connection_id: authorised.connection_id,
            limits: authorised.selection.limits,
            initial_action_window: authorised.action_window,
            writer: Arc::new(Mutex::new(authorised.control_writer)),
            reader: Mutex::new(Some(authorised.control_reader)),
            streams,
        })
    }

    /// Returns a sender that can be held without the transport.
    #[must_use]
    pub fn sender(&self) -> ControlSender {
        ControlSender {
            writer: Arc::clone(&self.writer),
        }
    }
}

/// The QUIC application error code a client closes with.
pub const CLIENT_CLOSED: u32 = 0;

impl ControlTransport for NetworkTransport {
    fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    fn limits(&self) -> ReceiveLimits {
        self.limits
    }

    fn initial_action_window(&self) -> ActionWindow {
        self.initial_action_window.clone()
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            self.writer.lock().await.write_message(frame).await?;
            Ok(())
        })
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            let mut held = self.reader.lock().await;
            let reader = held.as_mut().ok_or(ClientError::ConnectionEnded)?;
            let frame = reader.read_message::<ControlFrame>().await?;
            if frame.is_none() {
                held.take();
            }
            Ok(frame)
        })
    }

    fn open_stream(&self, header: StreamHeader) -> TransportFuture<'_, DataStream> {
        Box::pin(async move { Ok(self.streams.open(&self.connection, header).await?) })
    }

    fn accept_stream(&self) -> TransportFuture<'_, DataStream> {
        Box::pin(async move { Ok(self.streams.accept(&self.connection).await?) })
    }

    fn revoke_streams(&self) {
        self.streams.revoke_all();
    }

    fn close(&self) {
        self.streams.revoke_all();
        self.connection
            .close(CLIENT_CLOSED.into(), b"the client closed the connection");
    }
}

/// A send-only handle on a control stream.
///
/// A frame is written under the lock from beginning to end. `SendStream::write_all` is not
/// cancellation safe, so a caller that drops a send part way through would otherwise leave a prefix
/// of one frame on the stream and the next frame would be read as its continuation; the writer
/// refuses to continue a stream an interrupted write left in pieces.
#[derive(Clone, Debug)]
pub struct ControlSender {
    writer: Arc<Mutex<FrameWriter>>,
}

impl ControlSender {
    /// Sends one control frame.
    ///
    /// # Errors
    ///
    /// Returns a framing or stream failure.
    pub async fn send(&self, frame: &ControlFrame) -> Result<()> {
        self.writer.lock().await.write_message(frame).await?;
        Ok(())
    }
}
