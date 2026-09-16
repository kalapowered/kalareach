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
use kr_ipc::framed::{FrameReader, FrameWriter};
use kr_ipc::paths::Endpoint;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{BuildId, ConnectionId, EnvironmentId};
use kr_protocol::local::{LocalClientKind, LocalPeer, LocalRole};
use tokio::sync::Mutex;

use crate::error::{ClientError, Result};
use crate::transport::{ControlTransport, TransportFuture};

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
#[derive(Debug)]
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
    /// Notified when this connection is closed, so an active read or write stops waiting.
    ending: tokio::sync::Notify,
    /// Set once a session has claimed the receive side.
    claimed: AtomicBool,
}

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
        let client = LocalClient::connect(endpoint, LocalClientKind::Cli, build_id).await?;
        let (reader, writer, acknowledgement) = client.into_halves();
        Ok(Self {
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
            ending: tokio::sync::Notify::new(),
            claimed: AtomicBool::new(false),
        })
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

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            // One frame at a time. A second caller waits for the first's turn rather than finding
            // an empty slot and reporting a connection that is perfectly alive as ended.
            let _turn = self.turn.lock().await;
            // The notification is registered *before* the last look at the flag, so a close that
            // lands between the two is delivered to this future rather than missed: a `Notified`
            // created afterwards would wait for the next notification, and there is not one.
            let closing = self.ending.notified();
            if self.has_closed() {
                return Err(ClientError::ConnectionEnded);
            }
            // The write half is taken out for the duration of the write, for the same reason the
            // read half is: a caller that drops this future part way through drops the half with
            // it, so a cancelled write closes the socket rather than leaving it on a transport
            // nobody is using. It cannot be resumed either — the frame writer refuses to continue
            // a stream an interrupted write left in pieces.
            let Some(mut writer) = self.writer.lock().await.take() else {
                return Err(ClientError::ConnectionEnded);
            };
            let outcome = tokio::select! {
                outcome = writer.write_message(frame) => outcome,
                // Closing while this was waiting for the socket. The half is dropped with this
                // future, which is what ends the connection rather than waiting for a peer that
                // may never read again.
                () = closing => return Err(ClientError::ConnectionEnded),
            };
            // A write that failed has ended this connection, and so has a close that arrived while
            // this one was in progress. Either way the half goes rather than going back.
            if outcome.is_ok() {
                let mut held = self.writer.lock().await;
                if !self.has_closed() {
                    *held = Some(writer);
                }
            }
            outcome?;
            Ok(())
        })
    }

    fn claim_receiver(&self) -> Result<()> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(ClientError::ConnectionEnded);
        }
        Ok(())
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
                return Err(ClientError::ConnectionEnded);
            };
            // A local frame reader reports the end of the stream as a failure rather than as an
            // absent message, because every local exchange has a next frame until the peer goes
            // away. To a session the two are one thing: the connection ended.
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
                Err(_) => Ok(None),
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

    #[test]
    fn a_local_connection_has_no_data_streams_to_revoke() {
        // The trait method exists for the network transport's benefit. Naming that here keeps the
        // empty implementation from reading as an oversight.
        const fn takes_a_transport<T: ControlTransport>() {}
        takes_a_transport::<IpcTransport>();
    }
}
