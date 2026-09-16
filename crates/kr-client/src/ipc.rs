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
    writer: Mutex<Option<FrameWriter>>,
    reader: Mutex<Option<FrameReader>>,
    closed: AtomicBool,
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
            writer: Mutex::new(Some(writer)),
            reader: Mutex::new(Some(reader)),
            closed: AtomicBool::new(false),
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
            if self.has_closed() {
                return Err(ClientError::ConnectionEnded);
            }
            let mut held = self.writer.lock().await;
            let writer = held.as_mut().ok_or(ClientError::ConnectionEnded)?;
            let outcome = writer.write_message(frame).await;
            // A write that failed has ended this connection, and so has a close that arrived while
            // this one was waiting for the socket. Either way the half goes now rather than at the
            // next call.
            if outcome.is_err() || self.has_closed() {
                held.take();
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
            let frame = reader.read_message::<ControlFrame>().await;
            match frame {
                Ok(frame) if !self.has_closed() => {
                    *self.reader.lock().await = Some(reader);
                    Ok(Some(frame))
                }
                Ok(_) | Err(_) => Ok(None),
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
        // Whichever half nothing is using is released here. A call that is in flight holds the
        // other one: a read holds it inside its own future, so cancelling that future drops it,
        // and a write releases it when it sees the flag. The socket closes once both are gone.
        if let Ok(mut held) = self.writer.try_lock() {
            held.take();
        }
        if let Ok(mut held) = self.reader.try_lock() {
            held.take();
        }
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
