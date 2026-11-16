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

use iroh::endpoint::{Connection, ConnectionError};
use iroh::{Endpoint, EndpointAddr};
use kr_crypto::connect::PairedPeer;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::StreamHeader;
use kr_protocol::hello::{ALPN, ActionWindow, ReceiveLimits};
use kr_protocol::ids::ConnectionId;
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::handshake::{self, LocalIdentity};
use kr_transport::scheduler::{SendLimits, StreamBudget};
use kr_transport::streams::{DataStream, StreamRegistry};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{ClientError, Result};

/// A boxed future, so the transport stays usable behind a trait object.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// The host a connection reaches and the user or device it acts as, as the transport authenticated
/// them.
///
/// The host keeps its record of an action under the actor that sent it, so an action can be asked
/// about again only to the same host and as the same actor. Whoever composed a request keeps this
/// with it, and a connection with another one refuses to send it. Neither member is a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Reach {
    /// The host: an environment identifier for a local host, the host's device identity for a
    /// paired one.
    pub host: String,
    /// The actor: the operating-system user a local host authenticated, or this device's
    /// identity on a paired host.
    pub actor: String,
}

crate::debug_as_name!(Reach);

/// Opens the data streams of one connection, each with its bounded header written first.
///
/// Only a transport that multiplexes streams has one ([`ControlTransport::stream_opener`]): a local
/// socket carries the same control frames and has no streams to open.
pub trait StreamOpener: Send + Sync + std::fmt::Debug {
    /// Opens a data stream under `header`.
    ///
    /// The open waits for the host's stream credit and holds one of the connection's bulk slots
    /// while it waits, and the write of the header waits for the host to take it. Neither has a
    /// bound of its own, so a caller that must not wait for ever bounds the whole open itself; a
    /// dropped open gives its slot back.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ConnectionEnded`] when the sign-in the connection was opened under
    /// has ended, and otherwise the bulk-limit refusal, a failure of the connection that says its
    /// control stream is lost, or a stream failure.
    fn open(&self, header: StreamHeader) -> TransportFuture<'_, DataStream>;

    /// Resolves once the connection's streams have been revoked, which is when its control stream
    /// has ended or the sign-in it was opened under has: at once when that is already so. A caller
    /// that holds no stream of its own, and so cannot see its stream revoked, waits on this to
    /// learn that the connection is gone.
    fn revoked(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// The connection's send budget, which a writer whose write the budget refused for room waits on
    /// ([`StreamBudget::released`]) and then tries again. An opener that cannot say has none, and a
    /// writer that meets the refusal then ends its stream.
    fn budget(&self) -> Option<Arc<StreamBudget>> {
        None
    }
}

/// A connection this device ended itself, and why: the error the connection's calls are answered
/// with, and what a person is asked to do after its words. A stop whose words say their own next
/// step asks nothing more; one that states only a fact asks what the code of the error gives.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceEnd {
    /// The error the connection's calls are answered with.
    pub error: ProtocolError,
    /// What a person is asked to do after the error's words.
    pub action: crate::retry::UserAction,
}

crate::debug_fields!(DeviceEnd { action });

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

    /// Returns the host this connection reaches and the actor it acts as, or none for a transport
    /// that cannot say, whose requests are never asked about again.
    fn reach(&self) -> Option<Reach> {
        None
    }

    /// Why this device ended the connection itself, in the words a person is told and with what the
    /// person is asked to do after them, when it did: the account the connection was opened under
    /// signed out or was replaced, or the connection presents no lease of its own and the keeper of
    /// that account's lease holds none the host took, in which case the words and the action are
    /// the keeper's stop's. A transport that ends only as the host or the network ends it, or has
    /// not ended, says none. Asking also settles whether the account has changed since the
    /// connection was opened, so that answer is the latest one; a connection that presents no
    /// lease of its own is ended for want of a lease only when a request is sent on it. A transport
    /// that wraps another forwards the question or loses the words.
    fn ended_by_this_device(&self) -> Option<DeviceEnd>;

    /// Sends one control frame.
    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()>;

    /// Sends one control frame unless `not_after` has passed, or `wanted` has come to say no, and
    /// says whether it was written whole.
    ///
    /// A caller whose request is only good for a bounded time, and only while something it read
    /// before sending still holds, sends this way, so that the time spent waiting for the writer
    /// or for the connection to take the frame counts against it, and what changed meanwhile stops
    /// it. A transport looks before the frame is started and again before every write that hands
    /// bytes to the connection.
    ///
    /// `false` means the frame was not written whole, and the peer acts on none of it: either none
    /// of it went and the connection is as it was, or the answer changed once the transport had
    /// begun to write it, and the connection's control stream was ended so that the peer reads a
    /// frame that never completes. A transport that cannot say whether a byte went when it stops a
    /// write it has begun ends the stream all the same. A failure of a write that was not stopped
    /// is the caller's to read as an outcome that is not known.
    ///
    /// The provided method looks once, before it asks the transport to send, which is all a
    /// transport can do whose writer it cannot see into.
    fn send_before<'a>(
        &'a self,
        frame: &'a ControlFrame,
        not_after: Instant,
        wanted: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> TransportFuture<'a, bool> {
        Box::pin(async move {
            if Instant::now() > not_after || !wanted() {
                return Ok(false);
            }
            self.send(frame).await?;
            Ok(true)
        })
    }

    /// Claims the right to read this connection, which exactly one session may hold.
    ///
    /// Two readers on one stream would divide the frames between them, so a session claims the
    /// receive side when it starts and a second claim is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ConnectionEnded`] when the receive side is already claimed.
    fn claim_receiver(&self) -> Result<()>;

    /// Reads the next control frame, or `None` when the stream ended without a failure: this
    /// transport's own close ended the read, or the peer finished the stream at a frame's boundary
    /// on a network connection.
    ///
    /// A read's end is classified by what the read itself returned and by a mark that the
    /// transport sets itself, before its own close touches the connection; it reads no record or
    /// flag that a later close can change. On the network a read whose own cause says that this
    /// side closed the connection ends cleanly only when the transport's own close was called, so
    /// a close that another part of the program made (the endpoint's) is an error. On the local
    /// link this side's close takes no read's result from it. Every other end is an error that
    /// carries what the read returned (on the network the connection's cause, typed as
    /// [`kr_transport::TransportError::StreamLost`]), and it stays that error when a close follows
    /// it. The local link reports the peer's end at a frame's boundary as an error, and also
    /// closes itself, and then returns `None`, after a write that was cut or failed part way.
    ///
    /// Only the holder of the claim calls this.
    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>>;

    /// Returns the opener of this connection's data streams, or none for a transport that has no
    /// data streams, which a route for an attachment stream refuses before it asks the host
    /// anything. A transport that wraps another forwards the question, adding what it checks when
    /// a stream opens.
    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>>;

    /// Revokes every data stream, which is what the end of the control stream means.
    fn revoke_streams(&self);

    /// Ends the connection.
    fn close(&self);

    /// Whether this side has ended the connection, which a send that cut a frame short does. It is
    /// read at once and never waits, so a caller that has just seen a send stop learns from it,
    /// before the control stream's own end is read, whether the connection went with it. Every
    /// transport answers; a transport that wraps another forwards the question.
    fn is_closed(&self) -> bool;

    /// Whether a frame can still be written on this connection. It is false once this side has
    /// ended the connection, and for a transport that can lose its writing half while the
    /// connection stands, from the moment that it has: a write that failed because the peer has
    /// gone leaves the connection open, so that what the peer sent before it went is still read,
    /// and leaves nothing to write with.
    ///
    /// It is read at once and never waits. A call is admitted only while it is true, so that a
    /// call made after the writing side was lost is refused as not sent, and not registered and
    /// answered with an outcome that is not known. A transport that wraps another forwards the
    /// question.
    fn can_send(&self) -> bool {
        !self.is_closed()
    }
}

/// A connection to a paired host over iroh.
pub struct NetworkTransport {
    connection: Connection,
    connection_id: ConnectionId,
    limits: ReceiveLimits,
    initial_action_window: ActionWindow,
    writer: Arc<Mutex<FrameWriter>>,
    reader: Mutex<Option<FrameReader>>,
    /// Set once a session has claimed the receive side.
    claimed: std::sync::atomic::AtomicBool,
    /// Stored by this wrapper's own [`ControlTransport::close`], before it touches the connection:
    /// whether the connection had already ended when the close was made. A read's end is the clean
    /// end for this side's close only when the read's own cause says that this side closed the
    /// connection and this mark says that the close was made while the connection stood.
    own_close: OwnCloseMark,
    streams: Arc<StreamRegistry>,
    opener: Arc<NetworkStreams>,
    reach: Reach,
}

crate::debug_fields!(NetworkTransport { connection_id });

impl NetworkTransport {
    /// Dials a paired host and completes the handshake.
    ///
    /// The host record is the client's own paired record of the host, not something the host sends:
    /// the proof is checked against what this device already knows.
    ///
    /// # Errors
    ///
    /// Returns a transport failure, including the host's refusal when the handshake fails. When the
    /// attempt ran out without a connection while the relay status still showed a relay on the
    /// route refusing this device, the failure is [`kr_transport::TransportError::RelayRefused`]:
    /// it names that relay, what it said and what may still work, rather than a host that did not
    /// answer. A device with nothing but relays to try ends the attempt as soon as the status shows
    /// every relay on its route refusing it or its upgrade.
    pub async fn connect(
        endpoint: &Endpoint,
        host_addr: impl Into<EndpointAddr>,
        identity: &LocalIdentity,
        host_record: &PairedPeer,
        send_limits: SendLimits,
    ) -> Result<Self> {
        send_limits.check()?;
        let connection = kr_transport::endpoint::connect(endpoint, host_addr, ALPN).await?;
        let authorised = handshake::connect(&connection, identity, host_record).await?;
        let streams = Arc::new(StreamRegistry::with_limits(
            authorised.connection_id,
            Arc::new(StreamBudget::new(
                send_limits.negotiated(authorised.selection.limits),
            )),
            None,
            authorised.selection.limits,
        ));
        let opener = Arc::new(NetworkStreams {
            connection: connection.clone(),
            streams: Arc::clone(&streams),
        });
        Ok(Self {
            connection,
            connection_id: authorised.connection_id,
            limits: authorised.selection.limits,
            initial_action_window: authorised.action_window,
            writer: Arc::new(Mutex::new(authorised.control_writer)),
            reader: Mutex::new(Some(authorised.control_reader)),
            claimed: std::sync::atomic::AtomicBool::new(false),
            own_close: OwnCloseMark::new(),
            streams,
            opener,
            reach: Reach {
                host: format!("host:{}", host_record.device_id),
                actor: format!("device:{}", identity.device_id),
            },
        })
    }

    /// Finishes the control stream's sending half while the connection stands, as a client that
    /// ends its control stream and keeps its data streams does.
    ///
    /// # Errors
    ///
    /// Returns a stream error when the stream was closed already.
    #[cfg(feature = "testing")]
    pub async fn finish_control(&self) -> Result<()> {
        self.writer.lock().await.finish()?;
        Ok(())
    }

    /// Why the host ended the connection, once it has: the close's code and words.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn close_reason(&self) -> Option<iroh::endpoint::ConnectionError> {
        self.connection.close_reason()
    }

    /// Resets the control stream's sending half while the connection stands.
    #[cfg(feature = "testing")]
    pub async fn reset_control(&self) {
        self.writer.lock().await.reset();
    }

    /// Returns a sender that can be held without the transport.
    #[must_use]
    pub fn sender(&self) -> ControlSender {
        ControlSender {
            writer: Arc::clone(&self.writer),
        }
    }
}

/// The data streams of a connection to a paired host.
struct NetworkStreams {
    connection: Connection,
    streams: Arc<StreamRegistry>,
}

crate::debug_as_name!(NetworkStreams);

impl StreamOpener for NetworkStreams {
    fn open(&self, header: StreamHeader) -> TransportFuture<'_, DataStream> {
        Box::pin(async move { Ok(self.streams.open(&self.connection, header).await?) })
    }

    fn revoked(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.streams.revoked())
    }

    fn budget(&self) -> Option<Arc<StreamBudget>> {
        Some(Arc::clone(self.streams.budget()))
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

    fn reach(&self) -> Option<Reach> {
        Some(self.reach.clone())
    }

    fn ended_by_this_device(&self) -> Option<DeviceEnd> {
        None
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            self.writer.lock().await.write_message(frame).await?;
            Ok(())
        })
    }

    fn send_before<'a>(
        &'a self,
        frame: &'a ControlFrame,
        not_after: Instant,
        wanted: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> TransportFuture<'a, bool> {
        Box::pin(async move {
            // The writer is shared with every other sender on this connection: the time and what
            // the caller wants are looked at once the lock is held, and then before every byte
            // the stream takes, so that a stream with no room until after the time never carries
            // the frame.
            let Ok(mut writer) = tokio::time::timeout_at(not_after, self.writer.lock()).await
            else {
                return Ok(false);
            };
            let admits = |attempt: &mut dyn FnMut()| {
                if Instant::now() > not_after || !wanted() {
                    return false;
                }
                attempt();
                true
            };
            // Asked before anything is written, so that a frame refused at once leaves the stream
            // whole.
            if !admits(&mut || {}) {
                return Ok(false);
            }
            // The wait for room ends with the time. A frame abandoned after part of it went leaves
            // the stream in pieces, so the stream is reset and carries nothing more: the peer reads
            // a frame that never completes.
            let outcome =
                tokio::time::timeout_at(not_after, writer.write_message_while(frame, &admits))
                    .await;
            match outcome {
                Ok(sent) => Ok(sent?),
                Err(_) => {
                    writer.reset();
                    Ok(false)
                }
            }
        })
    }

    fn claim_receiver(&self) -> Result<()> {
        if self.claimed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Err(ClientError::ConnectionEnded);
        }
        Ok(())
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            let mut held = self.reader.lock().await;
            let reader = held.as_mut().ok_or(ClientError::ConnectionEnded)?;
            // A read's end is classified by what the read itself returned and by this wrapper's
            // own mark. The mark was stored by the owner's close before it touched the connection
            // and says whether the connection had already ended at that close, so a close that
            // follows the read's return cannot change what it says about an end that came first.
            // The connection's record is read nowhere here.
            let frame = match reader.read_message::<ControlFrame>().await {
                Ok(frame) => frame,
                Err(error) => end_of_a_failed_read(error, self.own_close.get())?,
            };
            if frame.is_none() {
                held.take();
            }
            Ok(frame)
        })
    }

    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        Some(Arc::clone(&self.opener) as Arc<dyn StreamOpener>)
    }

    fn revoke_streams(&self) {
        self.streams.revoke_all();
    }

    fn close(&self) {
        // The connection's record is read here, once and for its existence alone, before the close
        // changes it, and the mark is stored before the connection is closed, so that a read that
        // the close ends finds it set.
        self.own_close.close_with(
            || self.connection.close_reason().is_some(),
            || {
                self.streams.revoke_all();
                self.connection
                    .close(CLIENT_CLOSED.into(), b"the client closed the connection");
            },
        );
    }

    /// Whether the connection's record says that a local close ended it: the library records
    /// `LocallyClosed` when the application calls `close`. That record is the LAST cause written to
    /// the connection and not the first: this side's close writes it over a close by the peer, and
    /// the endpoint's own close (the pool's, under a live connection) writes it too, for a short
    /// time, before the record becomes the endpoint driver's end. A send that is cut short resets
    /// its stream and leaves the connection open, so this does not answer for that. It answers
    /// whether a write may be tried, and no read's end depends on it: a read is classified by the
    /// cause it returned and by this wrapper's own mark.
    fn is_closed(&self) -> bool {
        matches!(
            self.connection.close_reason(),
            Some(ConnectionError::LocallyClosed)
        )
    }

    /// Whether a frame can still be written: true only while the library records no close of
    /// either side. After the host's close, a reset, an idle timeout or a protocol error the
    /// library refuses every write before a byte goes, and the session's read loop may not have
    /// read to the end yet, so a call admitted in that time would be registered and answered as not
    /// known. This is a different question from [`ControlTransport::is_closed`], which is true for
    /// this side's close alone. A send that is cut short resets its stream and leaves the
    /// connection open, so this does not answer for that.
    fn can_send(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

/// What this wrapper's own close found when it was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnClose {
    /// The close was not made.
    NotMade,
    /// The connection had not ended: this wrapper's close ended it.
    WhileOpen,
    /// The connection had already ended by another cause (the peer's close, a reset, a timeout or
    /// the endpoint's close): this wrapper's close came after that end.
    AfterEnd,
}

/// The owner's close, recorded: stored once, by the first close, before the connection is closed.
struct OwnCloseMark(std::sync::atomic::AtomicU8);

impl OwnCloseMark {
    const NOT_MADE: u8 = 0;
    const WHILE_OPEN: u8 = 1;
    const AFTER_END: u8 = 2;

    const fn new() -> Self {
        Self(std::sync::atomic::AtomicU8::new(Self::NOT_MADE))
    }

    fn get(&self) -> OwnClose {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            Self::WHILE_OPEN => OwnClose::WhileOpen,
            Self::AFTER_END => OwnClose::AfterEnd,
            _ => OwnClose::NotMade,
        }
    }

    /// Makes the owner's close in this order: asks `ended` whether the connection had already
    /// ended, stores the mark that the answer gives, and only then runs `close`, which closes the
    /// connection. A later close keeps the first mark, since it sees the end that the first close
    /// made and would otherwise take the clean end from a read that the first close ended.
    fn close_with(&self, ended: impl FnOnce() -> bool, close: impl FnOnce()) {
        if self.0.load(std::sync::atomic::Ordering::Acquire) == Self::NOT_MADE {
            let mark = if ended() {
                Self::AFTER_END
            } else {
                Self::WHILE_OPEN
            };
            // Another close that came first keeps its mark.
            let _ = self.0.compare_exchange(
                Self::NOT_MADE,
                mark,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
        }
        close();
    }
}

/// What the end of a failed read of the control stream is: the one place that gives each cause its
/// end.
///
/// The cause that the read itself returned decides, with this wrapper's own mark. A cause of
/// "closed by this side" ends the read as the clean end only when this wrapper's own close was
/// made while the connection stood: with the mark that the close came after the connection's end
/// (the endpoint's close or the peer's came first), or with no mark (the endpoint's close under a
/// live connection, which this wrapper did not make), it is a failure. A connection closed by the
/// peer, lost for another reason or failed in its stream keeps its cause as a failure whatever the
/// mark says, and keeps it when a close follows, since the cause was returned before. The inner
/// match names every cause of the transport's type, with no catch-all.
fn end_of_a_failed_read(
    error: kr_transport::TransportError,
    own_close: OwnClose,
) -> Result<Option<ControlFrame>> {
    use kr_transport::{ConnectionEnd, TransportError};
    match error {
        TransportError::StreamLost(cause) => match cause {
            ConnectionEnd::ClosedBySelf if own_close == OwnClose::WhileOpen => Ok(None),
            ConnectionEnd::ClosedBySelf
            | ConnectionEnd::ClosedByPeer(_)
            | ConnectionEnd::Lost(_) => Err(TransportError::StreamLost(cause).into()),
        },
        // Every other failure of the stream or the frame, and any variant that the transport adds
        // later: a failure.
        other => Err(other.into()),
    }
}

/// A send-only handle on a control stream.
///
/// A frame is written under the lock from beginning to end. `SendStream::write_all` is not
/// cancellation safe, so a caller that drops a send part way through would otherwise leave a prefix
/// of one frame on the stream and the next frame would be read as its continuation; the writer
/// refuses to continue a stream an interrupted write left in pieces.
#[derive(Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use kr_transport::{ConnectionEnd, TransportError};

    fn lost(cause: ConnectionEnd) -> TransportError {
        TransportError::StreamLost(cause)
    }

    /// Each cause that a failed read returned has its end, and the end reads nothing but the cause
    /// and this wrapper's own mark: the clean end needs the cause "closed by this side" and a close
    /// that this wrapper made while the connection stood. Every other cause is a failure that
    /// keeps its cause, whatever the mark says when the end is classified.
    #[test]
    fn each_cause_of_a_failed_read_has_its_end() {
        // A close by this side, made by this wrapper while the connection stood: the clean end.
        assert!(matches!(
            end_of_a_failed_read(lost(ConnectionEnd::ClosedBySelf), OwnClose::WhileOpen),
            Ok(None)
        ));
        // A close by this side that this wrapper did not make (the endpoint's), or that this
        // wrapper made after the connection had ended (the endpoint's or the peer's came first):
        // a failure.
        for mark in [OwnClose::NotMade, OwnClose::AfterEnd] {
            assert!(matches!(
                end_of_a_failed_read(lost(ConnectionEnd::ClosedBySelf), mark),
                Err(ClientError::Transport(TransportError::StreamLost(
                    ConnectionEnd::ClosedBySelf
                )))
            ));
        }
        // The host closed and the read returned that, whatever this side's close did or did not do
        // before or after: the host's cause is kept.
        for mark in [OwnClose::NotMade, OwnClose::WhileOpen, OwnClose::AfterEnd] {
            assert!(matches!(
                end_of_a_failed_read(lost(ConnectionEnd::ClosedByPeer("closed".into())), mark),
                Err(ClientError::Transport(TransportError::StreamLost(
                    ConnectionEnd::ClosedByPeer(_)
                )))
            ));
            assert!(matches!(
                end_of_a_failed_read(lost(ConnectionEnd::Lost("timed out".into())), mark),
                Err(ClientError::Transport(TransportError::StreamLost(
                    ConnectionEnd::Lost(_)
                )))
            ));
            // Any other failure of the stream: a failure, a close that follows or not.
            assert!(matches!(
                end_of_a_failed_read(TransportError::Stream("reset".into()), mark),
                Err(ClientError::Transport(TransportError::Stream(_)))
            ));
        }
    }

    /// The owner's close is made in one order: it asks whether the connection had already ended,
    /// stores the mark that the answer gives, and only then closes the connection. A close that
    /// follows keeps the first mark. The connection here is a flag that the close sets.
    #[test]
    fn the_owners_close_stores_what_the_connection_was_before_it_closes_it() {
        // The connection stands: the close is made while it is open, and the mark is already
        // stored when the connection is closed.
        let ended = std::cell::Cell::new(false);
        let mark = OwnCloseMark::new();
        assert_eq!(mark.get(), OwnClose::NotMade);
        let mut stored_at_the_close = None;
        mark.close_with(
            || ended.get(),
            || {
                ended.set(true);
                stored_at_the_close = Some(mark.get());
            },
        );
        assert_eq!(
            stored_at_the_close,
            Some(OwnClose::WhileOpen),
            "the mark was not stored, from the connection as it stood, before the connection was closed"
        );
        assert_eq!(mark.get(), OwnClose::WhileOpen);
        // A second close finds the end that the first one made, and keeps the first mark.
        mark.close_with(|| ended.get(), || {});
        assert_eq!(
            mark.get(),
            OwnClose::WhileOpen,
            "a later close took the mark of the first"
        );

        // The connection had ended already: the close is made after its end.
        let ended = std::cell::Cell::new(true);
        let mark = OwnCloseMark::new();
        let mut stored_at_the_close = None;
        mark.close_with(|| ended.get(), || stored_at_the_close = Some(mark.get()));
        assert_eq!(stored_at_the_close, Some(OwnClose::AfterEnd));
        assert_eq!(mark.get(), OwnClose::AfterEnd);
    }
}
