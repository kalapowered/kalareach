//! One bridge connection, with the direction of every frame enforced.
//!
//! The union on the wire is closed, and each side refuses the variants its role does not send. A
//! bridge that sent a [`BridgeFrame::Request`] would be trying to drive the worker's own machine;
//! a worker that sent a [`BridgeFrame::Event`] would be reporting a reader it does not have.
//! Neither is ignored: the connection ends, because a peer that misunderstands the direction of
//! this contract cannot be trusted with the fence.

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_protocol::ids::RequestId;
use kr_protocol::root::FencePublication;

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
        event: Box<crate::contract::events::BridgeEvent>,
    },
    /// The reader thread's answer to one request.
    Answer {
        /// The request being answered.
        id: RequestId,
        /// The answer.
        answer: Box<BridgeAnswer>,
    },
}

/// One accepted bridge connection, from the worker's side.
#[derive(Debug)]
pub struct BridgeLink {
    reader: FrameReader,
    writer: FrameWriter,
    next_request: u64,
}

impl BridgeLink {
    /// Wraps an accepted connection.
    #[must_use]
    pub fn new(connection: Connection) -> Self {
        let (reader, writer) = split(connection, BRIDGE_STREAM_KIND);
        Self {
            reader,
            writer,
            next_request: 0,
        }
    }

    /// Allocates the next request identifier on this connection.
    ///
    /// Each side allocates on its own side, so an answer belongs to its question rather than to
    /// whatever is currently in flight.
    pub fn next_request_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }

    /// Reads the next frame a bridge may send.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::WrongDirection`] for a frame only the worker sends, and
    /// [`HostError::Ipc`] when the connection ends or the frame is malformed.
    pub async fn recv(&mut self) -> Result<FromBridge> {
        let frame: BridgeFrame = self.reader.read_message().await?;
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
            BridgeFrame::Handshake(_) => Err(HostError::WrongDirection { frame: "handshake" }),
            BridgeFrame::EventResult { .. } => Err(HostError::WrongDirection {
                frame: "event_result",
            }),
            BridgeFrame::Request { .. } => Err(HostError::WrongDirection { frame: "request" }),
            BridgeFrame::FencePublished(_) => Err(HostError::WrongDirection {
                frame: "fence_published",
            }),
            BridgeFrame::LaunchRevoked { .. } => Err(HostError::WrongDirection {
                frame: "launch_revoked",
            }),
        }
    }

    /// Answers the opening frame.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_handshake(&mut self, outcome: &HandshakeOutcome) -> Result<()> {
        self.send(&BridgeFrame::Handshake(outcome.clone())).await
    }

    /// Answers one bridge event.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_event_result(&mut self, id: RequestId, result: EventOutcome) -> Result<()> {
        self.send(&BridgeFrame::EventResult { id, result }).await
    }

    /// Puts a request in front of the reader thread.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_request(&mut self, id: RequestId, request: WorkerRequest) -> Result<()> {
        self.send(&BridgeFrame::Request { id, request }).await
    }

    /// Tells the bridge whether a fence was published.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_publication(&mut self, publication: FencePublication) -> Result<()> {
        self.send(&BridgeFrame::FencePublished(publication)).await
    }

    /// Tells the bridge a launch transaction is over.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
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

    async fn send(&mut self, frame: &BridgeFrame) -> Result<()> {
        self.writer.write_message(frame).await?;
        Ok(())
    }
}
