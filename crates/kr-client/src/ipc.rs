//! The local half: a control transport over a Unix socket or a Windows named pipe.
//!
//! Section 23: local endpoints carry the same typed frames as a network connection, with local
//! peer authentication instead of a device proof. That is the whole of the difference, and this
//! module is where it lives:
//!
//! * the socket authenticates the operating-system caller before a frame is read, so there is no
//!   `hello` nonce to prove and no `kr-connect/1` transcript to sign;
//! * the host stamps the freshness context and hands it back in its acknowledgement — the
//!   connection identity, the action window, the environment, the boot and the caller it
//!   authenticated — and the client never asserts any of it;
//! * there are no data streams to multiplex, because a socket has none.
//!
//! Everything above the transport is unchanged. [`crate::Session`] is written against
//! [`ControlTransport`] and nothing else, so request correlation, action identifiers, receipts,
//! cursors and the action window behave identically whichever way the client connected, and a
//! native client on the host machine and a paired device on the far side of a relay run the same
//! code.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_ipc::client::LocalClient;
use kr_ipc::framed::{FrameReader, FrameWhile, FrameWriter};
use kr_ipc::paths::Endpoint;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{BuildId, ConnectionId, EnvironmentId};
use kr_protocol::local::{LocalClientKind, LocalPeer, LocalRole};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::{ClientError, Result};
use crate::transport::{ControlTransport, Reach, StreamOpener, TransportFuture};

/// What the host stamped on a local connection, in place of a device proof.
///
/// A network peer proves an authorisation key over a transcript and the host reads its device from
/// the paired record. A local caller proves nothing: the kernel already told the host who it is,
/// and the host says so here. Every field is the host's own answer, which is why a client only
/// reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalContext {
    /// Which host process answered.
    pub role: LocalRole,
    /// The environment this endpoint belongs to.
    pub environment_id: EnvironmentId,
    /// The boot the host is running.
    pub boot_identity: BootIdentity,
    /// The operating-system caller the host authenticated.
    pub peer: LocalPeer,
}

/// A connection to a host on this machine.
pub struct IpcTransport {
    connection_id: ConnectionId,
    limits: ReceiveLimits,
    initial_action_window: ActionWindow,
    context: LocalContext,
    /// The two halves of the socket, each released as soon as nothing needs it.
    ///
    /// A local connection closes when both halves are dropped; there is nothing to tell a peer
    /// about, the way a QUIC connection has an application error code. So closing sets the flag
    /// and takes whichever half is not in use, and a call that is in flight releases its own half
    /// when it sees the flag.
    /// Whose turn it is to write. Frames do not interleave on one stream, and a caller that has
    /// to wait for another's frame is waiting rather than being told the connection ended.
    turn: Mutex<()>,
    writer: Mutex<Option<FrameWriter>>,
    reader: Mutex<Option<FrameReader>>,
    closed: AtomicBool,
    /// Set when a write failed because the peer has gone and the write half was dropped with it,
    /// with the connection left open for the read loop to read what the peer sent before it went.
    write_lost: AtomicBool,
    /// Notified when this connection is closed, so an active read or write stops waiting.
    ending: tokio::sync::Notify,
    /// Set once a session has claimed the receive side.
    claimed: AtomicBool,
}

crate::debug_fields!(IpcTransport { connection_id });

impl IpcTransport {
    /// Connects to a host endpoint on this machine and negotiates the protocol version.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal when nothing is listening, when the endpoint belongs to another
    /// user, or when no protocol major is shared.
    pub async fn connect(endpoint: &Endpoint, build_id: BuildId) -> Result<Self> {
        // A client, not a controller: a controller connection is the one that speaks for a
        // generation, and this library is what an attachment and a command line use.
        Self::connect_as(endpoint, LocalClientKind::Cli, build_id).await
    }

    /// Connects to a host endpoint on this machine as the companion app, and negotiates the
    /// protocol version.
    ///
    /// The host starts a session this connection creates with the environment of its own
    /// execution context, because an app has no shell of its own to take one from. The command
    /// line's [`Self::connect`] declares what it is, and so does this.
    ///
    /// # Errors
    ///
    /// As [`Self::connect`].
    pub async fn connect_app(endpoint: &Endpoint, build_id: BuildId) -> Result<Self> {
        Self::connect_as(endpoint, LocalClientKind::App, build_id).await
    }

    async fn connect_as(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
    ) -> Result<Self> {
        let client = LocalClient::connect(endpoint, kind, build_id).await?;
        Ok(Self::over(client))
    }

    /// Carries a connection the caller has already opened and checked.
    ///
    /// A session worker's endpoint is named by a descriptor on disk, and a descriptor is only data:
    /// before anything else crosses the connection the caller has the worker prove it holds the
    /// descriptor's key. That exchange is the caller's, on the client it opened, and this takes the
    /// client over once it is done. It is taken before any call, so nothing the host pushed is
    /// still held on it.
    #[must_use]
    pub fn over(client: LocalClient) -> Self {
        let (reader, writer, acknowledgement) = client.into_halves();
        Self {
            connection_id: acknowledgement.connection_id,
            limits: acknowledgement.max_receive,
            initial_action_window: acknowledgement.action_window,
            context: LocalContext {
                role: acknowledgement.role,
                environment_id: acknowledgement.environment_id,
                boot_identity: acknowledgement.boot_identity,
                peer: acknowledgement.peer,
            },
            turn: Mutex::new(()),
            writer: Mutex::new(Some(writer)),
            reader: Mutex::new(Some(reader)),
            closed: AtomicBool::new(false),
            write_lost: AtomicBool::new(false),
            ending: tokio::sync::Notify::new(),
            claimed: AtomicBool::new(false),
        }
    }

    /// Returns the freshness context the host stamped on this connection.
    #[must_use]
    pub const fn context(&self) -> &LocalContext {
        &self.context
    }

    /// Returns this transport behind the shared handle a session takes.
    #[must_use]
    pub fn shared(self) -> Arc<dyn ControlTransport> {
        Arc::new(self)
    }

    fn has_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// The host and the actor a local connection reaches and acts as, when it is to the control
/// daemon.
///
/// Only the control daemon keeps the record of an action that is asked about again. A session
/// worker's endpoint carries the same environment and user, and has no such record and no grant
/// method, so a request composed for the daemon is not sent to it. The host builds the actor a
/// local caller's actions are claimed under from the user it authenticated, and states that user
/// in its acknowledgement.
fn reach_of(context: &LocalContext) -> Option<Reach> {
    (context.role == LocalRole::Controller).then(|| Reach {
        host: context.environment_id.to_string(),
        actor: format!("local:{}", context.peer.uid.get()),
    })
}

/// How a frame put on the socket came out.
enum Written {
    /// Every byte of it is with the peer.
    Whole,
    /// The peer has none of it, and the stream is whole for the next frame.
    Withdrawn,
    /// The peer has part of it and the rest will not go: the stream is in pieces.
    Cut,
}

/// Puts `frame` on the socket, and stops while it can still be stopped: with a limit, the time
/// and the caller's wish are looked at before every write to the socket and again once the socket
/// has room, so a frame the socket would not take until after the limit never goes, and the wait
/// for room ends when the time does.
async fn put_on(
    writer: &mut FrameWriter,
    frame: &ControlFrame,
    limit: Option<(Instant, &(dyn Fn() -> bool + Send + Sync))>,
) -> Result<Written> {
    let Some((not_after, wanted)) = limit else {
        writer.write_message(frame).await?;
        return Ok(Written::Whole);
    };
    let framed = FrameWriter::encode(StreamKind::Control, frame)?;
    let mut may_write = || Instant::now() <= not_after && wanted();
    let outcome =
        tokio::time::timeout_at(not_after, writer.write_frame_while(&framed, &mut may_write)).await;
    Ok(match outcome {
        Ok(outcome) => match outcome? {
            FrameWhile::Sent => Written::Whole,
            FrameWhile::Withdrawn => Written::Withdrawn,
            FrameWhile::Cut => Written::Cut,
        },
        // The time ran out while the socket took nothing more: the frame is taken back when none
        // of it went, and is cut when part of it did.
        Err(_) => {
            if writer.withdraw_unstarted() {
                Written::Withdrawn
            } else {
                Written::Cut
            }
        }
    })
}

impl IpcTransport {
    /// Writes `frame` when this connection has its turn, unless `limit` says its time has passed
    /// or it is no longer wanted by then, and says whether it was written whole.
    ///
    /// A frame that is stopped part way is not finished: the connection ends, and the peer reads a
    /// frame that stops short and acts on nothing of it.
    async fn write(
        &self,
        frame: &ControlFrame,
        limit: Option<(Instant, &(dyn Fn() -> bool + Send + Sync))>,
    ) -> Result<bool> {
        // One frame at a time. A second caller waits for the first's turn rather than finding
        // an empty slot and reporting a connection that is perfectly alive as ended.
        let _turn = match limit {
            None => self.turn.lock().await,
            Some((not_after, _)) => {
                match tokio::time::timeout_at(not_after, self.turn.lock()).await {
                    Ok(turn) => turn,
                    Err(_) => return Ok(false),
                }
            }
        };
        if limit.is_some_and(|(not_after, wanted)| Instant::now() > not_after || !wanted()) {
            return Ok(false);
        }
        // The notification is registered *before* the last look at the flag, so a close
        // that lands between the two is delivered to this future rather than missed: a `Notified`
        // created afterwards would wait for the next notification, and there is not one.
        let closing = self.ending.notified();
        if self.has_closed() {
            return Err(ClientError::ConnectionEnded);
        }
        // The write half is taken out of its slot for the duration of the write, and `Lent` says
        // what a write that is dropped or that fails leaves behind: it cannot be resumed (the frame
        // writer refuses to continue a stream an interrupted write left in pieces), so a frame that
        // part of went ends the connection, and one that none of went gives the half back.
        let Some(half) = self.writer.lock().await.take() else {
            return Err(ClientError::ConnectionEnded);
        };
        let mut lent = Lent {
            transport: self,
            half: Some(half),
        };
        let outcome = tokio::select! {
            outcome = put_on(lent.half()?, frame, limit) => outcome,
            // Closing while this was waiting for the socket. The half is dropped with this
            // future, which is what ends the connection rather than waiting for a peer that
            // may never read again.
            () = closing => return Err(ClientError::ConnectionEnded),
        };
        // A cut frame ends the connection here, and so does a close that arrived while this write
        // was in progress: the half goes rather than going back.
        let written = match outcome {
            Ok(Written::Cut) => {
                lent.half.take();
                self.close();
                return Ok(false);
            }
            Ok(Written::Whole) => true,
            Ok(Written::Withdrawn) => false,
            // The peer has gone. The connection is not closed: what the peer sent before it went
            // (an answer, the last output, a refusal that names no request) is still in the socket
            // for the read loop, which reads to the peer's end and ends the session there. The half
            // is dropped with the failed write, and from this moment no frame can be written.
            Err(error) if says_the_peer_has_gone(&error) => {
                self.write_lost.store(true, Ordering::Release);
                lent.half.take();
                return Err(error);
            }
            // Any other failure is left to `Lent`, which closes the connection when part of the
            // frame went: nothing else would end a connection that holds the start of a frame.
            Err(error) => return Err(error),
        };
        let mut held = self.writer.lock().await;
        if !self.has_closed() {
            *held = lent.half.take();
        }
        Ok(written)
    }
}

/// Whether a failed write says that the peer has gone, which is the one failure after which the
/// connection is left open for its read loop to read to the peer's end, and not closed.
///
/// `kr_ipc` reads the system's answer to a write (and to a read) with one rule,
/// [`kr_ipc::error::peer_has_gone`], and reports it as [`kr_ipc::IpcError::PeerClosed`]: a broken
/// pipe, a reset and "not connected" on a Unix socket, and the broken-pipe and no-data errors of a
/// Windows named pipe, which the standard library reports as a broken pipe; and a write that took
/// no byte of a frame that has bytes. Every other failure of a write is not a peer that has gone,
/// and a connection that holds the start of a frame is closed rather than left with nothing to
/// end it.
const fn says_the_peer_has_gone(error: &ClientError) -> bool {
    matches!(error, ClientError::Ipc(kr_ipc::IpcError::PeerClosed))
}

/// The write half while one frame is put on it, and what becomes of it when the write does not
/// run to its end.
///
/// A write that is dropped part way, by a caller that stops waiting for it, would otherwise leave
/// the half in no slot and the connection standing: the read half keeps the socket open, the
/// session reads as standing, and every later write fails. So the guard decides. When part of a
/// frame went, the peer holds the start of a frame that will never be finished, and the connection
/// is closed, as it is when a bounded write is cut. When none of it went, the frame is taken back
/// and the half returns to its slot: the connection stands and the next frame is written as usual.
struct Lent<'a> {
    transport: &'a IpcTransport,
    half: Option<FrameWriter>,
}

impl Lent<'_> {
    fn half(&mut self) -> Result<&mut FrameWriter> {
        self.half.as_mut().ok_or(ClientError::ConnectionEnded)
    }
}

impl Drop for Lent<'_> {
    fn drop(&mut self) {
        let Some(mut half) = self.half.take() else {
            return;
        };
        if self.transport.has_closed() {
            return;
        }
        if half.is_mid_frame() && half.has_sent_any() {
            self.transport.close();
            return;
        }
        half.withdraw_unstarted();
        // The slot is empty and nothing else takes it while this write holds the turn; `close`
        // only looks at it without waiting, and it has not run, since the connection stands.
        if let Ok(mut held) = self.transport.writer.try_lock()
            && !self.transport.has_closed()
        {
            *held = Some(half);
        }
    }
}

impl ControlTransport for IpcTransport {
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
        reach_of(&self.context)
    }

    fn ended_by_this_device(&self) -> Option<kr_protocol::error::ProtocolError> {
        None
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            self.write(frame, None).await?;
            Ok(())
        })
    }

    fn send_before<'a>(
        &'a self,
        frame: &'a ControlFrame,
        not_after: Instant,
        wanted: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> TransportFuture<'a, bool> {
        Box::pin(async move { self.write(frame, Some((not_after, wanted))).await })
    }

    fn claim_receiver(&self) -> Result<()> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(ClientError::ConnectionEnded);
        }
        Ok(())
    }

    fn stream_opener(&self) -> Option<Arc<dyn StreamOpener>> {
        None
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            // As in `send`: the notification is registered before the flag is read, so a close
            // that lands in between reaches this future.
            let closing = self.ending.notified();
            if self.has_closed() {
                return Ok(None);
            }
            // The read half is taken out for the duration of the read and put back afterwards.
            // That is what makes a cancelled read close the socket: the reader lives in this
            // future while it waits, so dropping the future drops it. Leaving it in the slot would
            // mean a session that was closed while its reader was parked kept the socket, and the
            // worker's attachment with it, for as long as anything held the session.
            let Some(mut reader) = self.reader.lock().await.take() else {
                // No reader: either this side's close took it (it stores the flag before it takes
                // a half, so a slot that the close emptied always shows the flag, however the
                // close fell between the check above and this access), which is the clean end; or
                // an earlier read that failed or was cancelled left none, and nothing closed.
                return if self.has_closed() {
                    Ok(None)
                } else {
                    Err(ClientError::ConnectionEnded)
                };
            };
            // A local frame reader reports the end of the stream as a failure rather than as an
            // absent message, because every local exchange has a next frame until the peer goes
            // away. It is returned as that failure, as every other failed read is, so that what a
            // session reports of how its connection ended carries what the link said. A session
            // ends on either result alike. Only this side's own close is the clean end.
            let frame = tokio::select! {
                frame = reader.read_message::<ControlFrame>() => frame,
                () = closing => return Ok(None),
            };
            match frame {
                Ok(frame) => {
                    // The slot is taken before the flag is read again, so a close that lands while
                    // this read was waiting cannot be overtaken by the reinsertion.
                    let mut held = self.reader.lock().await;
                    if self.has_closed() {
                        return Ok(None);
                    }
                    *held = Some(reader);
                    Ok(Some(frame))
                }
                // This side's close causes no read error: it takes only the halves that are idle and
                // abandons a read that waits, so a read that returned an error failed for its own
                // reason, and keeps it, a close that follows or not.
                Err(error) => Err(ClientError::Ipc(error)),
            }
        })
    }

    fn revoke_streams(&self) {
        // A socket has no data streams to revoke. Section 23's revocation is about the streams a
        // network connection authorised, and a local connection authorises none: its output,
        // input and attachment chunks all travel as control frames.
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // Whichever half nothing is using is released here, and whatever is in flight is told to
        // stop: a read or a write that is waiting for the socket abandons it and drops the half it
        // is holding. The socket closes once both are gone.
        if let Ok(mut held) = self.writer.try_lock() {
            held.take();
        }
        if let Ok(mut held) = self.reader.try_lock() {
            held.take();
        }
        self.ending.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.has_closed()
    }

    fn can_send(&self) -> bool {
        !self.has_closed() && !self.write_lost.load(Ordering::Acquire)
    }
}

impl Drop for IpcTransport {
    fn drop(&mut self) {
        // Both halves go with the transport, whether or not anything called `close`. A socket that
        // outlived its transport would keep whatever it is attached to on the host alive with it.
        self.writer.get_mut().take();
        self.reader.get_mut().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request composed for the control daemon is not repeated on a session worker's endpoint,
    /// which has the same environment and user and none of the daemon's records.
    #[test]
    fn only_the_control_daemon_has_a_reach() {
        use kr_protocol::identity::{BootIdentity, BootIdentitySource};
        use kr_protocol::scalars::{Bytes, Nullable, U64};

        let context = |role| LocalContext {
            role,
            environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16])),
            boot_identity: BootIdentity {
                source: BootIdentitySource::BootTime,
                value: Bytes::new(vec![1]),
            },
            peer: LocalPeer {
                uid: U64::new(501),
                gid: U64::new(20),
                pid: Nullable::null(),
            },
        };
        let daemon = reach_of(&context(LocalRole::Controller)).expect("the daemon states one");
        assert!(daemon.actor.ends_with("501"));
        assert_eq!(reach_of(&context(LocalRole::Worker)), None);
        assert_eq!(reach_of(&context(LocalRole::Rendezvous)), None);
    }

    #[test]
    fn a_local_connection_has_no_data_streams_to_revoke() {
        // The trait method exists for the network transport's benefit. Naming that here keeps the
        // empty implementation from reading as an oversight.
        const fn takes_a_transport<T: ControlTransport>() {}
        takes_a_transport::<IpcTransport>();
    }

    use kr_protocol::envelope::{Outcome, ParamsValue, Request, Response};
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::ids::RequestId;
    use kr_protocol::method::Method;
    use std::time::Duration;

    /// A transport over one end of a raw local connection, and the other end, which the case plays.
    /// There is no handshake: what these cases look at is the writing half.
    async fn over_a_raw_connection() -> (
        IpcTransport,
        FrameReader,
        FrameWriter,
        kr_ipc::testing::TempHost,
    ) {
        let tree = kr_ipc::testing::TempHost::create();
        let endpoint = tree
            .paths()
            .environment(tree.environment_id())
            .controller_endpoint()
            .expect("a controller endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a local endpoint");
        let accepting = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.expect("accepts");
            (connection, listener)
        });
        let client = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects");
        let (served, _listener) = accepting.await.expect("the accepting task");
        let (reader, writer) = kr_ipc::framed::split(client, StreamKind::Control);
        let (peer_reader, peer_writer) = kr_ipc::framed::split(served, StreamKind::Control);
        let connection_id = ConnectionId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        let transport = IpcTransport {
            connection_id,
            limits: ReceiveLimits::default(),
            initial_action_window: ActionWindow {
                action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                    .expect("a window identifier"),
                connection_id,
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
            },
            context: LocalContext {
                role: LocalRole::Controller,
                environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16])),
                boot_identity: kr_protocol::identity::BootIdentity {
                    source: kr_protocol::identity::BootIdentitySource::BootTime,
                    value: kr_protocol::scalars::Bytes::new(vec![1]),
                },
                peer: LocalPeer {
                    uid: kr_protocol::scalars::U64::new(501),
                    gid: kr_protocol::scalars::U64::new(20),
                    pid: kr_protocol::scalars::Nullable::null(),
                },
            },
            turn: Mutex::new(()),
            writer: Mutex::new(Some(writer)),
            reader: Mutex::new(Some(reader)),
            closed: AtomicBool::new(false),
            write_lost: AtomicBool::new(false),
            ending: tokio::sync::Notify::new(),
            claimed: AtomicBool::new(false),
        };
        (transport, peer_reader, peer_writer, tree)
    }

    /// A request frame with `padding` bytes in its params.
    fn request(id: u64, padding: usize) -> ControlFrame {
        ControlFrame::Request(Request {
            request_id: RequestId::new(id),
            method: Method::SessionList.into(),
            method_version: Method::SessionList.entry().version,
            params: ParamsValue::from_typed(&"x".repeat(padding)).expect("params"),
        })
    }

    fn answer(id: u64, outcome: Outcome) -> ControlFrame {
        ControlFrame::Response(Response {
            request_id: RequestId::new(id),
            outcome,
        })
    }

    fn request_id_of(frame: &ControlFrame) -> RequestId {
        match frame {
            ControlFrame::Request(request) => request.request_id,
            ControlFrame::Response(response) => response.request_id,
            other => panic!("a frame that these cases never send: {other:?}"),
        }
    }

    /// A write that is dropped after its frame went whole leaves the connection standing: the
    /// peer holds the whole of the frame, nothing is cut, and the half goes back to its slot for
    /// the next frame.
    #[tokio::test]
    async fn a_write_dropped_after_its_frame_went_whole_leaves_the_connection_standing() {
        let (transport, mut peer_reader, _peer_writer, _tree) = over_a_raw_connection().await;
        let mut half = transport.writer.lock().await.take().expect("the half");
        half.write_message(&request(1, 8)).await.expect("whole");
        assert!(half.has_sent_any() && !half.is_mid_frame());
        drop(Lent {
            transport: &transport,
            half: Some(half),
        });
        assert!(
            !transport.is_closed() && transport.can_send(),
            "a frame that went whole is not a reason to close the connection"
        );
        transport
            .send(&request(2, 8))
            .await
            .expect("the next frame is written");
        for id in [1, 2] {
            let frame = tokio::time::timeout(
                Duration::from_secs(8),
                peer_reader.read_message::<ControlFrame>(),
            )
            .await
            .expect("the peer reads the frame")
            .expect("a frame");
            assert_eq!(request_id_of(&frame), RequestId::new(id));
        }
    }

    /// A failed write with part of a frame sent whose error does not say that the peer has gone
    /// closes the connection: it holds the start of a frame and nothing else would end it. The
    /// failure is made by writing on a writer that already holds part of a frame, which a write
    /// never leaves behind and which the frame writer refuses with an error of its own.
    #[tokio::test]
    async fn a_failed_write_that_does_not_say_the_peer_has_gone_closes_the_connection() {
        let (transport, _peer_reader, _peer_writer, _tree) = over_a_raw_connection().await;
        let mut half = transport.writer.lock().await.take().expect("the half");
        let framed =
            FrameWriter::encode(StreamKind::Control, &request(1, 900_000)).expect("encodes");
        half.begin_frame(&framed).expect("begins");
        assert!(
            half.is_mid_frame() && half.has_sent_any(),
            "the socket of a peer that reads nothing takes part of the frame"
        );
        *transport.writer.lock().await = Some(half);
        let failed = transport.send(&request(2, 8)).await;
        assert!(
            matches!(
                &failed,
                Err(ClientError::Ipc(kr_ipc::IpcError::Socket { .. }))
            ),
            "an error that is not the peer's going: {failed:?}"
        );
        assert!(
            transport.is_closed() && !transport.can_send(),
            "the connection holds the start of a frame, so it is closed"
        );
    }

    /// A failed write with part of a frame sent whose error says that the peer has gone does not
    /// close the connection: the peer wrote its last frames before it went, and every one of them
    /// is read, then the end. No frame can be written from then on.
    #[tokio::test]
    async fn a_failed_write_to_a_peer_that_has_gone_leaves_what_it_sent_to_be_read() {
        let (transport, peer_reader, mut peer_writer, _tree) = over_a_raw_connection().await;
        let transport = std::sync::Arc::new(transport);
        let big = request(1, 900_000);
        let sending = tokio::spawn({
            let transport = std::sync::Arc::clone(&transport);
            async move { transport.send(&big).await }
        });
        // The peer reads nothing, so part of the frame goes and the write waits for room.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!sending.is_finished(), "the frame did not fit the socket");
        peer_writer
            .write_message(&answer(7, Outcome::Ok(ParamsValue::empty())))
            .await
            .expect("the answer");
        peer_writer
            .write_message(&answer(
                0,
                Outcome::Error(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this connection is refused",
                )),
            ))
            .await
            .expect("the refusal");
        // The peer goes with part of the frame unread.
        drop((peer_reader, peer_writer));
        let failed = tokio::time::timeout(Duration::from_secs(8), sending)
            .await
            .expect("the write ended")
            .expect("the task");
        assert!(
            matches!(&failed, Err(ClientError::Ipc(kr_ipc::IpcError::PeerClosed))),
            "{failed:?}"
        );
        assert!(
            !transport.is_closed(),
            "the connection stands, for its reader to read to the peer's end"
        );
        assert!(!transport.can_send(), "nothing can be written any more");
        let mut read = Vec::new();
        loop {
            match transport.recv().await {
                Ok(Some(frame)) => read.push(request_id_of(&frame)),
                // The peer's end at a frame's boundary is the link's own failure, which the end of
                // a session carries; it is no clean end, which is this side's own close.
                Err(ClientError::Ipc(kr_ipc::IpcError::PeerClosed)) => break,
                other => panic!("a read that is neither a frame nor the peer's end: {other:?}"),
            }
        }
        assert_eq!(
            read,
            [RequestId::new(7), RequestId::new(0)],
            "every frame the peer sent before it went is read"
        );
    }

    use crate::ordered::{Ended, Ordered, OrderedEvents};

    const WITHIN: Duration = Duration::from_secs(8);

    fn notice() -> ControlFrame {
        ControlFrame::Notification(kr_protocol::envelope::Notification {
            stream_id: kr_protocol::ids::StreamId::new("session.output").expect("a stream"),
            sequence: kr_protocol::ids::EventSequence::new(0),
            event_type: kr_protocol::ids::EventType::new("terminal.output").expect("an event type"),
            payload: ParamsValue::empty(),
        })
    }

    /// A frame whose length prefix is whole and whose payload no decoder reads.
    fn undecodable_frame() -> Vec<u8> {
        let mut framed = FrameWriter::encode(StreamKind::Control, &request(1, 8)).expect("encodes");
        for byte in &mut framed[kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN..] {
            *byte = 0xff;
        }
        framed
    }

    async fn an_ordered_session_over_a_raw_connection() -> (
        crate::session::Session,
        OrderedEvents,
        FrameReader,
        FrameWriter,
        kr_ipc::testing::TempHost,
    ) {
        let (transport, peer_reader, peer_writer, tree) = over_a_raw_connection().await;
        let (session, events) =
            crate::session::Session::start_ordered(std::sync::Arc::new(transport), 4)
                .expect("an ordered session");
        (session, events, peer_reader, peer_writer, tree)
    }

    async fn the_next_item(events: &mut OrderedEvents) -> Option<Ordered> {
        tokio::time::timeout(WITHIN, events.recv())
            .await
            .expect("the channel gave an item in time")
    }

    /// The peer's end at a frame's boundary is a failed read that says what the link said, and no
    /// clean end: a clean end is this side's own close.
    #[tokio::test]
    async fn the_peer_going_at_a_frames_boundary_is_a_failed_read() {
        let (transport, peer_reader, peer_writer, _tree) = over_a_raw_connection().await;
        drop((peer_reader, peer_writer));
        let read = tokio::time::timeout(WITHIN, transport.recv())
            .await
            .expect("the read ended");
        assert!(
            matches!(read, Err(ClientError::Ipc(kr_ipc::IpcError::PeerClosed))),
            "{read:?}"
        );
    }

    #[tokio::test]
    async fn a_frame_cut_short_is_a_failed_read() {
        let (transport, peer_reader, mut peer_writer, _tree) = over_a_raw_connection().await;
        let framed = FrameWriter::encode(StreamKind::Control, &request(1, 8)).expect("encodes");
        peer_writer
            .write_frame(&framed[..framed.len() - 2])
            .await
            .expect("the start of a frame");
        drop((peer_reader, peer_writer));
        let read = tokio::time::timeout(WITHIN, transport.recv())
            .await
            .expect("the read ended");
        assert!(
            matches!(
                read,
                Err(ClientError::Ipc(kr_ipc::IpcError::TruncatedFrame { .. }))
            ),
            "{read:?}"
        );
    }

    #[tokio::test]
    async fn a_frame_that_cannot_be_decoded_is_a_failed_read() {
        let (transport, _peer_reader, mut peer_writer, _tree) = over_a_raw_connection().await;
        peer_writer
            .write_frame(&undecodable_frame())
            .await
            .expect("a frame");
        let read = tokio::time::timeout(WITHIN, transport.recv())
            .await
            .expect("the read ended");
        assert!(
            matches!(read, Err(ClientError::Ipc(kr_ipc::IpcError::Frame(_)))),
            "{read:?}"
        );
    }

    /// This side's own close ends a read that waits and every read after it, with no failure.
    #[tokio::test]
    async fn this_sides_own_close_is_a_clean_end_of_the_read() {
        let (transport, _peer_reader, _peer_writer, _tree) = over_a_raw_connection().await;
        let transport = std::sync::Arc::new(transport);
        let waiting = tokio::spawn({
            let transport = std::sync::Arc::clone(&transport);
            async move { transport.recv().await }
        });
        transport.close();
        let read = tokio::time::timeout(WITHIN, waiting)
            .await
            .expect("the read ended")
            .expect("the task");
        assert!(matches!(read, Ok(None)), "{read:?}");
        assert!(matches!(transport.recv().await, Ok(None)));
    }

    /// On a real local link a session's end carries the link's failure, after the notification that
    /// came before it.
    #[tokio::test]
    async fn an_ordered_session_ends_with_the_peers_end_on_the_local_link() {
        let (session, mut events, peer_reader, mut peer_writer, _tree) =
            an_ordered_session_over_a_raw_connection().await;
        peer_writer
            .write_message(&notice())
            .await
            .expect("a notification");
        drop((peer_reader, peer_writer));
        assert!(matches!(
            the_next_item(&mut events).await,
            Some(Ordered::Notification(_))
        ));
        assert!(matches!(
            the_next_item(&mut events).await,
            Some(Ordered::Ended(Ended::Failed(ClientError::Ipc(
                kr_ipc::IpcError::PeerClosed
            ))))
        ));
        assert!(the_next_item(&mut events).await.is_none());
        drop(session);
    }

    #[tokio::test]
    async fn an_ordered_session_ends_with_the_decoders_text_on_a_frame_that_cannot_be_decoded() {
        let (session, mut events, _peer_reader, mut peer_writer, _tree) =
            an_ordered_session_over_a_raw_connection().await;
        peer_writer
            .write_frame(&undecodable_frame())
            .await
            .expect("a frame");
        assert!(matches!(
            the_next_item(&mut events).await,
            Some(Ordered::Ended(Ended::Failed(ClientError::Ipc(
                kr_ipc::IpcError::Frame(_)
            ))))
        ));
        assert!(the_next_item(&mut events).await.is_none());
        drop(session);
    }

    /// The order that the flag check at the entry cannot show: the owner closes after the entry's
    /// check and before the slot is read, and takes the reader (the close stores its flag first).
    /// The slot is then found absent with the flag set: the clean end. The slot's lock is held here
    /// to hold that order, with no wait.
    #[tokio::test]
    async fn a_slot_the_owners_close_emptied_is_the_clean_end() {
        let (transport, _peer_reader, _peer_writer, _tree) = over_a_raw_connection().await;
        let transport = std::sync::Arc::new(transport);
        let mut slot = transport.reader.lock().await;
        let reading = tokio::spawn({
            let transport = std::sync::Arc::clone(&transport);
            async move { transport.recv().await }
        });
        // The read passes its flag check and waits for the slot.
        tokio::task::yield_now().await;
        transport.close();
        slot.take();
        drop(slot);
        let read = tokio::time::timeout(WITHIN, reading)
            .await
            .expect("the read ended")
            .expect("the task");
        assert!(matches!(read, Ok(None)), "{read:?}");
    }

    /// A slot that no close emptied (an earlier read failed or was cancelled and left no reader) is
    /// a failure with its words, and stays one.
    #[tokio::test]
    async fn a_slot_that_no_close_emptied_is_a_failure() {
        let (transport, _peer_reader, _peer_writer, _tree) = over_a_raw_connection().await;
        transport.reader.lock().await.take();
        let read = tokio::time::timeout(WITHIN, transport.recv())
            .await
            .expect("the read ended");
        assert!(
            matches!(read, Err(ClientError::ConnectionEnded)),
            "{read:?}"
        );
    }

    /// An error that the read returned stays a failure when the owner's flag lands after it: this
    /// side's close causes no read error, so no flag turns an error into the clean end. The flag is
    /// raised alone, as the first step of a close, which holds the order with no wait.
    #[tokio::test]
    async fn an_error_the_read_returned_is_kept_when_the_flag_lands_after_it() {
        let (transport, peer_reader, peer_writer, _tree) = over_a_raw_connection().await;
        let transport = std::sync::Arc::new(transport);
        let reading = tokio::spawn({
            let transport = std::sync::Arc::clone(&transport);
            async move { transport.recv().await }
        });
        tokio::task::yield_now().await;
        transport.closed.store(true, Ordering::Release);
        drop((peer_reader, peer_writer));
        let read = tokio::time::timeout(WITHIN, reading)
            .await
            .expect("the read ended")
            .expect("the task");
        assert!(
            matches!(read, Err(ClientError::Ipc(kr_ipc::IpcError::PeerClosed))),
            "{read:?}"
        );
    }

    /// The owner's own close, with the reader parked in a read of the real link, is the clean end.
    #[tokio::test]
    async fn an_ordered_session_the_owner_closes_ends_cleanly_on_the_local_link() {
        let (session, mut events, _peer_reader, _peer_writer, _tree) =
            an_ordered_session_over_a_raw_connection().await;
        session.close();
        assert!(matches!(
            the_next_item(&mut events).await,
            Some(Ordered::Ended(Ended::Finished))
        ));
        assert!(the_next_item(&mut events).await.is_none());
    }
}
