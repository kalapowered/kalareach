//! One bridge connection, split into the half that reads and the half that writes.
//!
//! The two halves are separate for the same reason the worker's own endpoints split them: the
//! driver reads the reader's answers on one task and sends it requests from another, and a send
//! that is waiting for a slow peer must not stop the answer to the last request from arriving. A
//! single handle would make the 250 ms hold depend on socket backpressure.
//!
//! The union on the wire is closed, and each side refuses the variants its role does not send. A
//! bridge that sent a [`BridgeFrame::Request`] would be trying to drive the worker's own machine;
//! a worker that sent a [`BridgeFrame::Event`] would be reporting a reader it does not have.
//! Neither is ignored and neither is survivable: the half that saw it is poisoned, so the next
//! call fails too and the connection is finished rather than carrying on in a state where one side
//! has misunderstood the direction of this contract.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_protocol::ids::RequestId;
use kr_protocol::root::FencePublication;

use crate::contract::events::BridgeEvent;
use crate::contract::requests::{
    BridgeAnswer, LaunchRejectionReason, LaunchTransactionId, WorkerRequest,
};
use crate::contract::transport::{
    BRIDGE_STREAM_KIND, BridgeFrame, BridgeHello, EventOutcome, HandshakeOutcome,
};
use crate::host::error::{HostError, Result};

/// What a bridge sent the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FromBridge {
    /// The opening frame.
    Hello(Box<BridgeHello>),
    /// Something the reader did.
    Event {
        /// The bridge's own identifier for this event.
        id: RequestId,
        /// What happened.
        event: Box<BridgeEvent>,
    },
    /// The reader thread's answer to one request.
    Answer {
        /// The request being answered.
        id: RequestId,
        /// The answer.
        answer: Box<BridgeAnswer>,
    },
}

/// Whether this connection is still usable.
///
/// Shared by both halves, because a direction failure on either of them ends the whole connection:
/// the peer has shown it does not understand the contract, and the other half's frames would be
/// going to or coming from that same peer.
#[derive(Clone, Debug, Default)]
struct Live(Arc<AtomicBool>);

impl Live {
    fn open() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(HostError::ConnectionFinished)
    }

    fn finish(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Splits an accepted connection into its reading and writing halves.
#[must_use]
pub fn accept(connection: Connection) -> (BridgeReader, BridgeWriter) {
    let (reader, writer) = split(connection, BRIDGE_STREAM_KIND);
    let live = Live::open();
    (
        BridgeReader {
            reader,
            live: live.clone(),
        },
        BridgeWriter {
            writer,
            live,
            next_request: 0,
        },
    )
}

/// The half that reads what a bridge sends.
#[derive(Debug)]
pub struct BridgeReader {
    reader: FrameReader,
    live: Live,
}

impl BridgeReader {
    /// Reads the next frame a bridge may send.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::WrongDirection`] for a frame only the worker sends, which also finishes
    /// the connection, [`HostError::ConnectionFinished`] afterwards, and [`HostError::Ipc`] when
    /// the connection ends or a frame is malformed.
    pub async fn recv(&mut self) -> Result<FromBridge> {
        self.live.check()?;
        let frame: BridgeFrame = match self.reader.read_message_without_schema().await {
            Ok(frame) => frame,
            Err(error) => {
                self.live.finish();
                return Err(error.into());
            }
        };
        let wrong = |frame: &'static str| HostError::WrongDirection { frame };
        match frame {
            BridgeFrame::Hello(hello) => Ok(FromBridge::Hello(Box::new(hello))),
            BridgeFrame::Event { id, event } => Ok(FromBridge::Event {
                id,
                event: Box::new(event),
            }),
            BridgeFrame::Answer { id, answer } => Ok(FromBridge::Answer {
                id,
                answer: Box::new(answer),
            }),
            BridgeFrame::Handshake(_) => {
                self.live.finish();
                Err(wrong("handshake"))
            }
            BridgeFrame::EventResult { .. } => {
                self.live.finish();
                Err(wrong("event_result"))
            }
            BridgeFrame::Request { .. } => {
                self.live.finish();
                Err(wrong("request"))
            }
            BridgeFrame::FencePublished(_) => {
                self.live.finish();
                Err(wrong("fence_published"))
            }
            BridgeFrame::LaunchRevoked { .. } => {
                self.live.finish();
                Err(wrong("launch_revoked"))
            }
        }
    }

    /// Ends this connection, so nothing more is read from it or written to it.
    pub fn finish(&self) {
        self.live.finish();
    }
}

/// The half that sends the worker's own frames.
#[derive(Debug)]
pub struct BridgeWriter {
    writer: FrameWriter,
    live: Live,
    next_request: u64,
}

impl BridgeWriter {
    /// Allocates the next request identifier on this connection.
    ///
    /// Each side allocates on its own side, so an answer belongs to its question rather than to
    /// whatever is currently in flight.
    pub const fn next_request_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }

    /// Answers the opening frame.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectionFinished`] when the connection has ended and
    /// [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_handshake(&mut self, outcome: &HandshakeOutcome) -> Result<()> {
        self.send(&BridgeFrame::Handshake(outcome.clone())).await
    }

    /// Answers one bridge event.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectionFinished`] when the connection has ended and
    /// [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_event_result(&mut self, id: RequestId, result: EventOutcome) -> Result<()> {
        self.send(&BridgeFrame::EventResult { id, result }).await
    }

    /// Puts a request in front of the reader thread.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectionFinished`] when the connection has ended and
    /// [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_request(&mut self, id: RequestId, request: WorkerRequest) -> Result<()> {
        self.send(&BridgeFrame::Request { id, request }).await
    }

    /// Tells the bridge whether a fence was published.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectionFinished`] when the connection has ended and
    /// [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_publication(&mut self, publication: FencePublication) -> Result<()> {
        self.send(&BridgeFrame::FencePublished(publication)).await
    }

    /// Tells the bridge a launch transaction is over.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectionFinished`] when the connection has ended and
    /// [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_revocation(
        &mut self,
        transaction: LaunchTransactionId,
        reason: LaunchRejectionReason,
    ) -> Result<()> {
        self.send(&BridgeFrame::LaunchRevoked {
            transaction,
            reason,
        })
        .await
    }

    /// Ends this connection, so nothing more is written to it or read from it.
    pub fn finish(&self) {
        self.live.finish();
    }

    /// Returns true while this connection is still usable.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live.check().is_ok()
    }

    async fn send(&mut self, frame: &BridgeFrame) -> Result<()> {
        self.live.check()?;
        // A frame the peer had no room for is retained by the writer until it is finished, and
        // anything else written now would push the rest of it out first. So a write that fails
        // ends the connection rather than leaving half a frame with the peer.
        match self.writer.write_message(frame).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.live.finish();
                Err(error.into())
            }
        }
    }
}
